# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
#
# Compatibility with the names used before KLone was renamed Klin, for one
# release: KLONE_* settings, <klone/...> headers, klone_conf.h, the klone_*
# and KLONE_* names and, on install, the klone and kloned commands. Remove
# this file (and its three calls in CMakeLists.txt) in the next release.

# KLONE_* settings (-DKLONE_SITE_DIR=...) set the KLIN_* ones, with a warning.
# Called before the option() and set(CACHE) declarations, which keep a normal
# variable that is already set.
macro(klone_compat_options)
    foreach(_kc_name DEBUG ENABLE_SUP_FS ENABLE_SUP_CGI ENABLE_HOOKS
            ENABLE_WARNINGS STACK_PROTECTOR INSTALL_DAEMON_ONLY WITH_OPENSSL
            WITH_ZLIB DAEMON_NAME SITE_DIR IMPORT_ARGS WEBAPP_SOURCES)
        if(DEFINED KLONE_${_kc_name} AND NOT DEFINED KLIN_${_kc_name})
            message(DEPRECATION
                "KLONE_${_kc_name} is now KLIN_${_kc_name} (KLone was renamed Klin)")
            set(KLIN_${_kc_name} "${KLONE_${_kc_name}}")
        endif()
    endforeach()
endmacro()

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
        install(CODE "
            set(_d \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${_dir}\")
            file(CREATE_LINK \"${_target}\" \"\${_d}/${_name}\" SYMBOLIC)
            message(STATUS \"Installing: \${_d}/${_name} -> ${_target}\")
        ")
    endforeach()
endfunction()
