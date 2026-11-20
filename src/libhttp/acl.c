/*
 * Copyright (c) 2026 Daniel Tillett
 * All rights reserved.
 *
 * This file is part of Klin (derived from KLone), and as such it is subject to the license stated
 * in the LICENSE file which you have received as part of this distribution.
 */

/* IP access control (doc/ACCESS): a server's or vhost's "access" block
 * holds rules, each for some paths (or all), with "allow" and "deny"
 * lines of addresses and networks. The first rule whose path matches
 * decides, with its first line that names the client's address; a client
 * no line names is let in. Rules for every path are also applied when a
 * connection is accepted, before the TLS handshake: a denied client is
 * dropped at once. The address is the socket's peer: behind a proxy it is
 * the proxy's. */

#include "klin_conf.h"
#include <string.h>
#ifdef OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <u/libu.h>
#include <klin/acl.h>
#include <klin/http.h>
#include <klin/request.h>
#include <klin/vhost.h>

/* an address, IPv4 kept as an IPv4-mapped IPv6 address so both compare */
typedef struct { unsigned char a[16]; } acl_addr_t;

static int acl_parse_addr(const char *s, size_t len, acl_addr_t *ad)
{
    char buf[64];
    struct in_addr v4;

    if(len == 0 || len >= sizeof buf)
        return ~0;
    memcpy(buf, s, len);
    buf[len] = '\0';

    if(inet_pton(AF_INET, buf, &v4) == 1)
    {
        memset(ad->a, 0, 10);
        ad->a[10] = ad->a[11] = 0xFF;
        memcpy(ad->a + 12, &v4, 4);
        return 0;
    }
    return inet_pton(AF_INET6, buf, ad->a) == 1 ? 0 : ~0;
}

/* the address part of a peer string: "1.2.3.4:5678" or "[::1]:5678" */
static int acl_peer_addr(const char *peer, acl_addr_t *ad)
{
    const char *e;

    if(peer == NULL)
        return ~0;
    if(peer[0] == '[')
    {
        if((e = strchr(peer, ']')) == NULL)
            return ~0;
        return acl_parse_addr(peer + 1, (size_t) (e - peer - 1), ad);
    }
    if((e = strrchr(peer, ':')) == NULL)
        e = peer + strlen(peer);
    return acl_parse_addr(peer, (size_t) (e - peer), ad);
}

/* parse one entry: "all", an address, or a network "addr/bits" (bits of
 * the IPv4 or IPv6 address as written) */
static int acl_parse_net(const char *s, size_t len, acl_addr_t *net,
        unsigned *bits)
{
    const char *slash = memchr(s, '/', len);
    size_t al = slash ? (size_t) (slash - s) : len, nl;
    unsigned long b;
    char *end, num[8];
    int v4;

    if(len == 3 && !strncasecmp(s, "all", 3))
    {
        memset(net->a, 0, 16);
        *bits = 0;
        return 0;
    }
    if(acl_parse_addr(s, al, net))
        return ~0;
    v4 = (memchr(s, ':', al) == NULL);  /* IPv4 is kept mapped (96 bits) */

    *bits = 128;
    if(slash)
    {
        nl = len - al - 1;
        if(nl == 0 || nl >= sizeof num)
            return ~0;
        memcpy(num, slash + 1, nl);
        num[nl] = '\0';
        b = strtoul(num, &end, 10);
        if(*end || b > (v4 ? 32UL : 128UL))
            return ~0;
        *bits = (unsigned) (v4 ? b + 96 : b);
    }
    return 0;
}

static int acl_in_net(const acl_addr_t *ad, const acl_addr_t *net,
        unsigned bits)
{
    unsigned full = bits / 8, rem = bits % 8;

    if(memcmp(ad->a, net->a, full))
        return 0;
    if(rem && ((ad->a[full] ^ net->a[full]) & (0xFF << (8 - rem)) & 0xFF))
        return 0;
    return 1;
}

/* does a list of entries (blank or comma separated) name the address?
 * ~0 if an entry is not valid */
static int acl_list_has(const char *list, const acl_addr_t *ad, int *found)
{
    const char *p, *e;
    acl_addr_t net;
    unsigned bits;

    *found = 0;
    for(p = list; p && *p; p = e)
    {
        p += strspn(p, " \t,");
        e = p + strcspn(p, " \t,");
        if(e == p)
            continue;
        if(acl_parse_net(p, (size_t) (e - p), &net, &bits))
            return ~0;
        if(ad && acl_in_net(ad, &net, bits))
            *found = 1;
    }
    return 0;
}

static int acl_rule_has_path(u_config_t *rule)
{
    return u_config_get_child(rule, "path") != NULL;
}

static int acl_rule_matches(u_config_t *rule, const char *path)
{
    u_config_t *pc;
    const char *pat;
    int i;

    if(!acl_rule_has_path(rule))
        return 1;
    for(i = 0; path && (pc = u_config_get_child_n(rule, "path", i)); ++i)
        if((pat = u_config_get_value(pc)) && !fnmatch(pat, path, 0))
            return 1;
    return 0;
}

/* the decision of a rule: 1 allow, 0 deny, -1 no line names the address */
static int acl_rule_decide(u_config_t *rule, const acl_addr_t *ad)
{
    u_config_t *line;
    const char *key;
    int i, found;

    for(i = 0; (line = u_config_get_child_n(rule, NULL, i)); ++i)
    {
        key = u_config_get_key(line);
        if(strcmp(key, "allow") && strcmp(key, "deny"))
            continue;
        if(acl_list_has(u_config_get_value(line), ad, &found) == 0 && found)
            return !strcmp(key, "allow");
    }
    return -1;
}

/* 0 to let the client in, ~0 to refuse it; 'path' NULL: at connection
 * time, only rules for every path apply */
static int acl_decide(u_config_t *access, const char *peer, const char *path)
{
    u_config_t *rule;
    acl_addr_t ad;
    int i, d;

    if(access == NULL)
        return 0;
    if(acl_peer_addr(peer, &ad))
        return 0;   /* not an IP client (e.g. a UNIX socket, CGI mode) */

    for(i = 0; (rule = u_config_get_child_n(access, "rule", i)); ++i)
    {
        if(path == NULL)
        {
            /* a connection is dropped only if the first rule (for every
               path) denies it: a rule for some paths before it may let the
               client in there */
            if(acl_rule_has_path(rule))
                return 0;
            return acl_rule_decide(rule, &ad) == 0 ? ~0 : 0;
        }
        if(!acl_rule_matches(rule, path))
            continue;
        /* the first rule for the path decides; no line naming the client:
           let in */
        d = acl_rule_decide(rule, &ad);
        return d == 0 ? ~0 : 0;
    }
    return 0;
}

/**
 * \brief   Check a request against the vhost's access rules
 *
 * \return \c 0 to serve it, ::HTTP_STATUS_FORBIDDEN otherwise
 */
int acl_check(http_t *h, request_t *rq)
{
    vhost_t *vhost;

    dbg_return_if (h == NULL || rq == NULL, HTTP_STATUS_FORBIDDEN);

    if((vhost = http_get_vhost(h, rq)) == NULL || vhost->access == NULL)
        return 0;

    return acl_decide(vhost->access, request_get_peer_addr(rq),
            request_get_filename(rq)) ? HTTP_STATUS_FORBIDDEN : 0;
}

/**
 * \brief   Check a new connection against the server's rules for every
 *          path (before the TLS handshake)
 *
 * \param access  the server's "access" block (may be NULL)
 * \param peer    the client address ("a.b.c.d:port" or "[v6]:port")
 *
 * \return \c 0 to serve it, \c ~0 to drop it
 */
int acl_check_conn(u_config_t *access, const char *peer)
{
    return acl_decide(access, peer, NULL);
}

/**
 * \brief   Load and check a vhost's "access" block when it is created (a
 *          bad entry stops the server)
 */
int acl_load(vhost_t *vhost)
{
    u_config_t *access, *rule, *line;
    const char *key;
    int i, j, found, lines;

    dbg_return_if (vhost == NULL, ~0);

    if((access = u_config_get_child(vhost->config, "access")) == NULL)
        return 0;

    for(i = 0; (rule = u_config_get_child_n(access, "rule", i)); ++i)
    {
        for(lines = 0, j = 0; (line = u_config_get_child_n(rule, NULL, j)); ++j)
        {
            key = u_config_get_key(line);
            if(!strcmp(key, "path"))
            {
                warn_err_ifm(u_config_get_value(line) == NULL,
                        "access: an empty path");
                continue;
            }
            warn_err_ifm(strcmp(key, "allow") && strcmp(key, "deny"),
                    "access: unknown key '%s' in a rule (path, allow, deny)",
                    key);
            warn_err_ifm(u_config_get_value(line) == NULL ||
                    acl_list_has(u_config_get_value(line), NULL, &found),
                    "access: bad address or network in '%s %s'", key,
                    u_config_get_value(line) ? u_config_get_value(line) : "");
            lines++;
        }
        warn_err_ifm(lines == 0, "access: a rule without allow or deny");
    }

    vhost->access = access;

    return 0;
err:
    return ~0;
}
