# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
#
# Compatibility with the names used before KLone was renamed Klin, for one
# release: KLONE_* settings, <klone/...> headers, klone_conf.h, the klone_*
# and KLONE_* names and, on install, the klone and kloned commands. Remove
# this file (and its three calls in CMakeLists.txt) in the next release.

# KLONE_* settings (-DKLONE_SITE_DIR=...) move to the KLIN_* cache entries,
# with a warning, and the KLONE_* entry is removed: the value then stays in
# the cache under its new name on every later configure. A KLONE_* entry is
# only there when it was just given, so it replaces any KLIN_* value (also
# one left from an earlier configure). Called before the option() and
# set(CACHE) declarations, which keep a cache entry that already exists.
function(klone_compat_options)
    foreach(_spec DEBUG:BOOL ENABLE_SUP_FS:BOOL ENABLE_SUP_CGI:BOOL
            ENABLE_HOOKS:BOOL ENABLE_WARNINGS:BOOL STACK_PROTECTOR:BOOL
            INSTALL_DAEMON_ONLY:BOOL WITH_OPENSSL:BOOL WITH_ZLIB:BOOL
            DAEMON_NAME:STRING SITE_DIR:PATH IMPORT_ARGS:STRING
            WEBAPP_SOURCES:STRING)
        string(REPLACE ":" ";" _spec "${_spec}")
        list(GET _spec 0 _name)
        list(GET _spec 1 _type)
        if(NOT DEFINED CACHE{KLONE_${_name}})
            continue()
        endif()
        message(DEPRECATION
            "KLONE_${_name} is now KLIN_${_name} (KLone was renamed Klin)")
        set(KLIN_${_name} "$CACHE{KLONE_${_name}}" CACHE ${_type}
            "Set from KLONE_${_name}" FORCE)
        unset(KLONE_${_name} CACHE)
    endforeach()
endfunction()

# <klone/X.h> for each <klin/X.h>, klone_conf.h and klone_compat.h, in the
# generated include directory (on the include path of Klin, the site and the
# install tree). file(CONFIGURE) leaves unchanged files alone.
function(klone_compat_headers include_dir)
    file(GLOB _headers RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/klin"
        "${CMAKE_CURRENT_SOURCE_DIR}/klin/*.h")
    foreach(_h IN LISTS _headers)
        # the umbrella header was <klone/klone.h>
        if(_h STREQUAL "klin.h")
            set(_old "klone.h")
        else()
            set(_old "${_h}")
        endif()
        file(CONFIGURE OUTPUT "${include_dir}/klone/${_old}" @ONLY CONTENT
"/* KLone was renamed Klin: this header will be removed in the next release,
 * include <klin/@_h@> instead */
#include <klin/@_h@>
#include \"klone_compat.h\"
")
    endforeach()
    file(CONFIGURE OUTPUT "${include_dir}/klone_conf.h" CONTENT
"/* KLone was renamed Klin: this header will be removed in the next release,
 * include klin_conf.h instead */
#include \"klin_conf.h\"
#include \"klone_compat.h\"
")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/klone_compat.h"
        "${include_dir}/klone_compat.h" COPYONLY)
endfunction()

# Install the compatibility headers and, on Unix, klone and kloned as links
# to klin and klind (kloned only when the daemon keeps its default name).
function(klone_compat_install include_dir)
    if(NOT KLIN_INSTALL_DAEMON_ONLY)
        install(DIRECTORY "${include_dir}/klone"
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
        install(FILES "${include_dir}/klone_conf.h" "${include_dir}/klone_compat.h"
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    endif()
    if(WIN32)
        return()
    endif()
    set(_links "")
    if(KLIN_DAEMON_NAME STREQUAL "klind")
        list(APPEND _links "${CMAKE_INSTALL_SBINDIR}|klind|kloned")
    endif()
    if(NOT KLIN_INSTALL_DAEMON_ONLY)
        list(APPEND _links "${CMAKE_INSTALL_BINDIR}|klin|klone")
    endif()
    foreach(_link IN LISTS _links)
        string(REPLACE "|" ";" _parts "${_link}")
        list(GET _parts 0 _dir)
        list(GET _parts 1 _target)
        list(GET _parts 2 _name)
        # the directory as install(TARGETS) uses it: an absolute one as is,
        # a relative one under the install prefix; DESTDIR goes in front
        install(CODE "
            set(_d \"${_dir}\")
            if(NOT IS_ABSOLUTE \"\${_d}\")
                set(_d \"\${CMAKE_INSTALL_PREFIX}/\${_d}\")
            endif()
            set(_d \"\$ENV{DESTDIR}\${_d}\")
            file(CREATE_LINK \"${_target}\" \"\${_d}/${_name}\" SYMBOLIC)
            message(STATUS \"Installing: \${_d}/${_name} -> ${_target}\")
        ")
    endforeach()
endfunction()
