# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
# Klin CMake build. Replaces the MaKL configure script and GNU makefiles;
# works with single-configuration generators (Ninja, BSD or GNU make, ...).
#
#   cmake -S . -B out -G Ninja -DKLIN_SITE_DIR=/path/to/site
#   cmake --build out
cmake_minimum_required(VERSION 3.24)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" _klin_version)
string(STRIP "${_klin_version}" _klin_version)
# Same optimisation as the legacy build (and no NDEBUG). Seeding the cache
# before project() keeps CMake's "-O3 -DNDEBUG" default from being added.
set(CMAKE_C_FLAGS_RELEASE "-O2" CACHE STRING "C flags for Release builds")
project(Klin VERSION ${_klin_version} LANGUAGES C)

get_property(_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(_multi_config)
    # the site sub-build and test runners assume one configuration per tree
    message(FATAL_ERROR "Multi-configuration generators (${CMAKE_GENERATOR}) are "
        "not supported; use Ninja or a Makefile generator with CMAKE_BUILD_TYPE.")
endif()

include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CheckIncludeFiles)
include(CheckStructHasMember)
include(CheckSymbolExists)
include(ExternalProject)
include(GNUInstallDirs)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# names from before KLone was renamed Klin (for one release)
include(cmake/klone_compat.cmake)
klone_compat_options()

# Options (legacy configure equivalents in brackets)
option(KLIN_DEBUG "Debug logging and symbols [--enable_debug]" OFF)
option(LIBU_DEBUG "Debug logging in LibU [--enable_libu_debug]" ${KLIN_DEBUG})
option(KLIN_ENABLE_SUP_FS "Serve files from the file system [--enable_sup_fs]" OFF)
option(KLIN_ENABLE_SUP_CGI "Run external CGIs [--enable_sup_cgi]" OFF)
option(KLIN_ENABLE_HOOKS "Call user-provided hooks_setup() [--enable_hooks]" OFF)
option(KLIN_ENABLE_WARNINGS "Extra compiler warnings [--enable_warns]" OFF)
option(KLIN_STACK_PROTECTOR "Use -fstack-protector-all when available" ON)
option(KLIN_INSTALL_DAEMON_ONLY "Install only the daemon [--install_daemon_only]" OFF)
option(KLIN_WITH_OPENSSL "HTTPS, encrypted pages and client sessions (OpenSSL 3)" ON)
option(KLIN_WITH_ZLIB "Compressed pages and responses (zlib)" ON)
option(LIBU_ENABLE_SCTP "Build LibU with SCTP support" OFF)
option(KLIN_BUILD_TESTS "Build the unit tests (run them with ctest)" OFF)
set(KLIN_DAEMON_NAME "klind" CACHE STRING "Name of the daemon [--daemon_name]")
set(KLIN_SITE_DIR "" CACHE PATH "Site directory to embed into klind (empty: none)")
set(KLIN_IMPORT_ARGS "" CACHE STRING
    "Extra 'klin -c import' options, e.g. -z;-x;*.bak (a CMake list)")
set(KLIN_WEBAPP_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/webapp/webapp.c" CACHE STRING
    "Web application sources linked into klind [WEBAPP_SRCS]")
set(LIBU_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libu" CACHE PATH "LibU checkout")

# Predictable output layout (used by the test and fuzz runners)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# C dialect: gnu99 with GNU89 inline semantics, as the sources expect
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

include(cmake/LibU.cmake)

# ---------------------------------------------------------------------------
# Platform checks (klin_conf.h)
# ---------------------------------------------------------------------------
if(WIN32)
    set(OS_WIN 1)
else()
    set(OS_UNIX 1)
endif()

set(CMAKE_REQUIRED_QUIET ON)
check_include_files("stdint.h" HAVE_STDINT)
check_include_files("getopt.h" HAVE_GETOPT)
check_include_files("unistd.h" HAVE_UNISTD)
check_include_files("sys/select.h" HAVE_SYS_SELECT)
check_include_files("sys/wait.h" HAVE_SYS_WAIT)
check_include_files("sys/types.h;sys/dir.h" HAVE_SYS_DIR)
check_include_files("sys/types.h;sys/socket.h" HAVE_SYS_SOCKET)
check_symbol_exists(LOG_PERROR "syslog.h" HAVE_LOG_PERROR)
check_symbol_exists(SA_RESTART "signal.h" HAVE_SA_RESTART)
check_symbol_exists(TCP_NODELAY "sys/types.h;netinet/tcp.h" HAVE_TCP_NODELAY)
check_c_source_compiles("#include <sys/types.h>\nint main(void) { pid_t p = 0; return (int) p; }" HAVE_PID_T)
check_struct_has_member("struct tm" tm_gmtoff "time.h" HAVE_STRUCT_TM_TM_GMTOFF)
check_c_source_compiles("#include <unistd.h>\n#include <sys/types.h>\nint main(void) { return fork() < 0; }" HAVE_FORK)
check_symbol_exists(syslog "syslog.h" HAVE_SYSLOG)
check_symbol_exists(mkstemp "stdlib.h;unistd.h" HAVE_MKSTEMP)
check_symbol_exists(localtime_r "time.h" HAVE_LOCALTIME_R)
check_c_source_compiles("static inline int f(void) { return 0; }\nint main(void) { return f(); }" HAVE_INLINE)
if(NOT CMAKE_CROSSCOMPILING)
    # va_list can be reused after being passed by value (build/va_list_by_value.c)
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/build/va_list_by_value.c" _va_src)
    check_c_source_runs("${_va_src}" VA_LIST_BY_VALUE)
endif()
unset(CMAKE_REQUIRED_QUIET)

if(KLIN_ENABLE_SUP_CGI AND WIN32)
    message(FATAL_ERROR "CGI is not supported on Windows")
endif()
set(ENABLE_SUP_FS ${KLIN_ENABLE_SUP_FS})
set(ENABLE_SUP_CGI ${KLIN_ENABLE_SUP_CGI})
set(ENABLE_HOOKS ${KLIN_ENABLE_HOOKS})
set(INSTALL_DAEMON_ONLY ${KLIN_INSTALL_DAEMON_ONLY})

if(KLIN_WITH_OPENSSL)
    find_package(OpenSSL 3.0 REQUIRED)
    set(HAVE_LIBOPENSSL 1)
    set(SSL_ON 1)
    set(SSL_OPENSSL 1)
endif()
if(KLIN_WITH_ZLIB)
    find_package(ZLIB REQUIRED)
    set(HAVE_LIBZ 1)
endif()

foreach(_d BINDIR SBINDIR SYSCONFDIR INCLUDEDIR LIBDIR LIBEXECDIR
        LOCALSTATEDIR DATADIR MANDIR DOCDIR)
    set(KLIN_FULL_${_d} "${CMAKE_INSTALL_FULL_${_d}}")
endforeach()

set(KLIN_GENERATED_INCLUDE_DIR "${CMAKE_BINARY_DIR}/include")
configure_file(cmake/klin_conf.h.in "${KLIN_GENERATED_INCLUDE_DIR}/klin_conf.h")
klone_compat_headers("${KLIN_GENERATED_INCLUDE_DIR}")

# ---------------------------------------------------------------------------
# Common compile settings
# ---------------------------------------------------------------------------
add_library(klin_settings INTERFACE)
# generated headers first, so stale in-tree ones from a legacy build lose
target_include_directories(klin_settings BEFORE INTERFACE
    "${KLIN_GENERATED_INCLUDE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(klin_settings INTERFACE HAVE_CONF_H
    $<$<BOOL:${KLIN_DEBUG}>:DEBUG>)
set(KLIN_C_OPTIONS "")
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    list(APPEND KLIN_C_OPTIONS -fgnu89-inline)
    if(KLIN_DEBUG)
        list(APPEND KLIN_C_OPTIONS -g)
    endif()
    if(KLIN_STACK_PROTECTOR)
        check_c_compiler_flag(-fstack-protector-all HAVE_STACK_PROTECTOR)
        if(HAVE_STACK_PROTECTOR)
            list(APPEND KLIN_C_OPTIONS -fstack-protector-all)
        endif()
    endif()
    if(KLIN_ENABLE_WARNINGS)
        list(APPEND KLIN_C_OPTIONS -W -Wall -Wstrict-prototypes
            -Wmissing-prototypes -Wpointer-arith -Wno-uninitialized
            -Wreturn-type -Wwrite-strings -Wswitch -Wshadow
            -Wunreachable-code -Wunused -Wcast-qual)
    endif()
endif()
target_compile_options(klin_settings INTERFACE ${KLIN_C_OPTIONS})
# Compile settings only: the static libraries link nothing themselves, so the
# executables can put them all in one rescan group (see klin_link_group).
target_include_directories(klin_settings INTERFACE
    $<TARGET_PROPERTY:libu,INTERFACE_INCLUDE_DIRECTORIES>
    $<$<BOOL:${KLIN_WITH_OPENSSL}>:${OPENSSL_INCLUDE_DIR}>
    $<$<BOOL:${KLIN_WITH_ZLIB}>:${ZLIB_INCLUDE_DIRS}>)
set(KLIN_SYSTEM_LIBS "")
if(KLIN_WITH_OPENSSL)
    list(APPEND KLIN_SYSTEM_LIBS OpenSSL::SSL OpenSSL::Crypto)
endif()
if(KLIN_WITH_ZLIB)
    list(APPEND KLIN_SYSTEM_LIBS ZLIB::ZLIB)
endif()
target_compile_options(libu PRIVATE ${KLIN_C_OPTIONS})

# ---------------------------------------------------------------------------
# Libraries (one per src/lib* directory, as in the legacy build)
# ---------------------------------------------------------------------------
function(klin_library name)
    add_library(klin_${name} STATIC ${ARGN})
    set_target_properties(klin_${name} PROPERTIES OUTPUT_NAME ${name})
    target_link_libraries(klin_${name} PUBLIC klin_settings)
endfunction()

set(_src "${CMAKE_CURRENT_SOURCE_DIR}/src")

klin_library(backend ${_src}/libbackend/backend.c)

set(_codec ${_src}/libcodec/codec.c ${_src}/libcodec/null.c)
if(HAVE_LIBZ)
    list(APPEND _codec ${_src}/libcodec/gzip.c)
endif()
if(SSL_OPENSSL)
    list(APPEND _codec ${_src}/libcodec/cipher.c)
endif()
klin_library(codec ${_codec})

klin_library(emb ${_src}/libemb/emb.c)

set(_http broker.c cgi.c http.c sup_emb.c access.c vhost.c dypage.c)
if(ENABLE_SUP_FS)
    list(APPEND _http sup_fs.c)
endif()
if(ENABLE_SUP_CGI)
    list(APPEND _http sup_cgi.c)
endif()
list(TRANSFORM _http PREPEND ${_src}/libhttp/)
klin_library(http ${_http})

set(_io io.c iofd.c iomem.c)
if(SSL_ON)
    list(APPEND _io iossl.c)
endif()
list(TRANSFORM _io PREPEND ${_src}/libio/)
klin_library(io ${_io})

set(_klog klog.c mem.c file.c common.c)
if(HAVE_SYSLOG)
    list(APPEND _klog syslog.c)
endif()
list(TRANSFORM _klog PREPEND ${_src}/libklog/)
klin_library(klog ${_klog})

set(_page field.c header.c request.c response.c rsfilter.c ses_file.c
    ses_mem.c session.c var.c vars.c)
if(SSL_ON)
    list(APPEND _page ses_client.c)
endif()
list(TRANSFORM _page PREPEND ${_src}/libpage/)
klin_library(page ${_page})

if(SSL_OPENSSL)
    klin_library(tls ${_src}/libtls/tls_glue.c ${_src}/libtls/tls.c)
endif()

set(_trans parser.c trans_c.c translat.c)
list(TRANSFORM _trans PREPEND ${_src}/libtrans/)
klin_library(trans ${_trans})

set(_utils utils.c md5.c mime_map.c timer.c date.c version.c path.c pwd.c)
list(TRANSFORM _utils PREPEND ${_src}/libutils/)
klin_library(utils ${_utils})

if(ENABLE_HOOKS)
    set(_hook hook.c server_nfy.c child_nfy.c req.c)
    list(TRANSFORM _hook PREPEND ${_src}/libhook/)
    klin_library(hook ${_hook})
endif()

add_library(klin_webapp STATIC ${KLIN_WEBAPP_SOURCES})
set_target_properties(klin_webapp PROPERTIES OUTPUT_NAME webapp)
target_link_libraries(klin_webapp PUBLIC klin_settings)

# The libraries depend on each other cyclically; GNU-style linkers need them
# grouped so the archives are rescanned. Other linkers rescan by themselves.
function(klin_link_group out)
    if(CMAKE_C_LINK_GROUP_USING_RESCAN_SUPPORTED
            OR CMAKE_LINK_GROUP_USING_RESCAN_SUPPORTED)
        set(${out} "$<LINK_GROUP:RESCAN,${ARGN}>" PARENT_SCOPE)
    else()
        set(${out} ${ARGN} PARENT_SCOPE)
    endif()
endfunction()

# ---------------------------------------------------------------------------
# klin: page translator and site importer
# ---------------------------------------------------------------------------
add_executable(klin ${_src}/tools/klin/main.c ${_src}/tools/klin/pm.c)
klin_link_group(_klin_libs klin_trans klin_codec klin_utils klin_io libu)
target_link_libraries(klin PRIVATE klin_settings ${_klin_libs} ${KLIN_SYSTEM_LIBS})

# ---------------------------------------------------------------------------
# Embedded site (external project: needs the klin tool at configure time)
# ---------------------------------------------------------------------------
set(KLIN_SITE_LIBRARY
    "${CMAKE_BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}site${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(_site_includes "${KLIN_GENERATED_INCLUDE_DIR}" "${LIBU_GENERATED_INCLUDE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}")
if(KLIN_WITH_OPENSSL)
    list(APPEND _site_includes "${OPENSSL_INCLUDE_DIR}")
endif()
if(KLIN_WITH_ZLIB)
    list(APPEND _site_includes ${ZLIB_INCLUDE_DIRS})
endif()
set(_site_defs HAVE_CONF_H)
if(KLIN_DEBUG)
    list(APPEND _site_defs DEBUG)
endif()
set(_site_dir "")
if(KLIN_SITE_DIR)
    get_filename_component(_site_dir "${KLIN_SITE_DIR}" ABSOLUTE
        BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
endif()
string(TOUPPER "${CMAKE_BUILD_TYPE}" _build_type)

# The site project's settings are written to an initial-cache script with
# every value in a bracket argument, so lists, quotes, backslashes and any
# other characters (flags such as -DSTR=\"x\", import patterns) arrive
# byte for byte. ExternalProject's own CMAKE_CACHE_ARGS lose one level of
# backslash escaping.
function(klin_cache_entry out name type value)
    foreach(_n RANGE 0 16)
        string(REPEAT "=" ${_n} _eq)
        string(FIND "${value}]${_eq}]" "]${_eq}]" _pos)
        string(LENGTH "${value}" _len)
        if(_pos EQUAL _len)     # the only closing delimiter is ours
            set(${out} "${${out}}set(${name} [${_eq}[${value}]${_eq}] CACHE ${type} \"\" FORCE)\n"
                PARENT_SCOPE)
            return()
        endif()
    endforeach()
    message(FATAL_ERROR "Cannot quote the value of ${name}")
endfunction()

set(_site_init "# Generated by Klin's CMakeLists.txt for the site sub-build\n")
foreach(_entry
        "CMAKE_MAKE_PROGRAM|FILEPATH|${CMAKE_MAKE_PROGRAM}"  # same build tool
        "CMAKE_C_COMPILER|FILEPATH|${CMAKE_C_COMPILER}"
        "CMAKE_TOOLCHAIN_FILE|FILEPATH|${CMAKE_TOOLCHAIN_FILE}"
        "CMAKE_BUILD_TYPE|STRING|${CMAKE_BUILD_TYPE}"
        "CMAKE_C_FLAGS|STRING|${CMAKE_C_FLAGS}"
        "CMAKE_C_FLAGS_${_build_type}|STRING|${CMAKE_C_FLAGS_${_build_type}}"
        "CMAKE_C_STANDARD|STRING|${CMAKE_C_STANDARD}"
        "CMAKE_C_EXTENSIONS|BOOL|${CMAKE_C_EXTENSIONS}"
        "KLIN_TOOL|FILEPATH|${CMAKE_BINARY_DIR}/bin/klin${CMAKE_EXECUTABLE_SUFFIX}"
        "KLIN_SITE_DIR|PATH|${_site_dir}"
        "KLIN_SITE_OUTPUT|FILEPATH|${KLIN_SITE_LIBRARY}")
    string(FIND "${_entry}" "|" _a)
    string(SUBSTRING "${_entry}" 0 ${_a} _name)
    math(EXPR _a "${_a} + 1")
    string(SUBSTRING "${_entry}" ${_a} -1 _rest)
    string(FIND "${_rest}" "|" _b)
    string(SUBSTRING "${_rest}" 0 ${_b} _type)
    math(EXPR _b "${_b} + 1")
    string(SUBSTRING "${_rest}" ${_b} -1 _value)
    klin_cache_entry(_site_init "${_name}" ${_type} "${_value}")
endforeach()
# list values (passed separately: a list inside the foreach would be split)
klin_cache_entry(_site_init KLIN_IMPORT_ARGS STRING "${KLIN_IMPORT_ARGS}")
klin_cache_entry(_site_init KLIN_SITE_INCLUDE_DIRS STRING "${_site_includes}")
klin_cache_entry(_site_init KLIN_SITE_DEFINITIONS STRING "${_site_defs}")
klin_cache_entry(_site_init KLIN_SITE_OPTIONS STRING "${KLIN_C_OPTIONS}")
# write only when changed, so an unchanged parent configure does not force a
# site reconfigure
set(_site_init_file "${CMAKE_BINARY_DIR}/site-init.cmake")
file(WRITE "${_site_init_file}.new" "${_site_init}")
configure_file("${_site_init_file}.new" "${_site_init_file}" COPYONLY)

ExternalProject_Add(klin_site_build
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake/site"
    BINARY_DIR "${CMAKE_BINARY_DIR}/site"
    CMAKE_ARGS -C "${_site_init_file}"
    BUILD_ALWAYS ON
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS "${KLIN_SITE_LIBRARY}"
    DEPENDS klin)
# reconfigure the site whenever its settings change
ExternalProject_Add_StepDependencies(klin_site_build configure "${_site_init_file}")

add_library(klin_site STATIC IMPORTED GLOBAL)
set_target_properties(klin_site PROPERTIES IMPORTED_LOCATION "${KLIN_SITE_LIBRARY}")
add_dependencies(klin_site klin_site_build)

# ---------------------------------------------------------------------------
# klind
# ---------------------------------------------------------------------------
set(_klind server.c main.c entry.c ppc.c atom.c ppc_log_add.c ppc_log_get.c
    ppc_nop.c child.c ppc_access_log.c)
if(OS_UNIX)
    list(APPEND _klind ppc_fork_child.c)
endif()
list(TRANSFORM _klind PREPEND ${_src}/klind/)
add_executable(klind ${_klind})
set_target_properties(klind PROPERTIES OUTPUT_NAME "${KLIN_DAEMON_NAME}")
add_dependencies(klind klin_site_build)

set(_klind_libs klin_http klin_utils klin_page klin_backend klin_emb klin_io)
if(SSL_OPENSSL)
    list(APPEND _klind_libs klin_tls)
endif()
list(APPEND _klind_libs klin_codec klin_klog)
if(ENABLE_HOOKS)
    list(APPEND _klind_libs klin_hook)
endif()
list(APPEND _klind_libs libu)
klin_link_group(_klind_group ${_klind_libs})
# Every page object is linked: the site is only referenced from libemb
# through register_pages(), after the site archive would have been scanned.
target_link_libraries(klind PRIVATE klin_settings
    "$<LINK_LIBRARY:WHOLE_ARCHIVE,klin_site>" klin_webapp ${_klind_group}
    ${KLIN_SYSTEM_LIBS})
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
    target_link_libraries(klind PRIVATE socket nsl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "QNX")
    target_link_libraries(klind PRIVATE socket)
elseif(WIN32)
    target_link_libraries(klind PRIVATE wsock32 bcrypt)
endif()

# ---------------------------------------------------------------------------
# API documentation (optional: 'cmake --build <dir> --target doc')
# ---------------------------------------------------------------------------
find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    set(KLIN_DOC_OUTPUT "${CMAKE_BINARY_DIR}/doc")
    configure_file(doc/doxy/kl1.doxy.in "${CMAKE_BINARY_DIR}/kl1.doxy" @ONLY)
    # the template's paths are relative to doc/doxy
    add_custom_target(doc
        COMMAND "${DOXYGEN_EXECUTABLE}" "${CMAKE_BINARY_DIR}/kl1.doxy"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/doc/doxy"
        COMMENT "Generating API documentation in ${KLIN_DOC_OUTPUT}"
        VERBATIM)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(TARGETS klind RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
if(NOT KLIN_INSTALL_DAEMON_ONLY)
    install(TARGETS klin RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    # Development files: everything needed to compile and link against Klin
    # from the install prefix alone (the Klin and LibU libraries, all Klin
    # headers, the generated klin_conf.h and LibU's headers and libu_conf.h).
    set(_klin_installed_libs klin_backend klin_codec klin_emb klin_http
        klin_io klin_klog klin_page klin_trans klin_utils klin_webapp libu)
    foreach(_lib klin_tls klin_hook)
        if(TARGET ${_lib})
            list(APPEND _klin_installed_libs ${_lib})
        endif()
    endforeach()
    install(TARGETS ${_klin_installed_libs} ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(FILES "${KLIN_SITE_LIBRARY}" DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(DIRECTORY klin/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/klin
        FILES_MATCHING PATTERN "*.h")
    install(FILES "${KLIN_GENERATED_INCLUDE_DIR}/klin_conf.h"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(DIRECTORY "${LIBU_GENERATED_INCLUDE_DIR}/u" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(FILES doc/man/klin.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
    install(FILES doc/man/klind.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
    install(FILES doc/man/klind.conf.5 DESTINATION ${CMAKE_INSTALL_MANDIR}/man5)
endif()
klone_compat_install("${KLIN_GENERATED_INCLUDE_DIR}")

# ---------------------------------------------------------------------------
# Package files: find_package(Klin) gives Klin::klin; pkg-config klin
# ---------------------------------------------------------------------------
if(NOT KLIN_INSTALL_DAEMON_ONLY)
    include(CMakePackageConfigHelpers)

    # the libraries an application links, in dependency order (the site and
    # webapp archives are klind's own)
    set(_klin_lib_names http utils page backend emb io)
    if(SSL_OPENSSL)
        list(APPEND _klin_lib_names tls)
    endif()
    list(APPEND _klin_lib_names codec klog)
    if(ENABLE_HOOKS)
        list(APPEND _klin_lib_names hook)
    endif()
    list(APPEND _klin_lib_names trans u)

    # paths relative to the installed files, so --prefix can change at
    # install time
    set(_klin_cmakedir "${CMAKE_INSTALL_LIBDIR}/cmake/Klin")
    file(RELATIVE_PATH _klin_config_up
        "${CMAKE_INSTALL_FULL_LIBDIR}/cmake/Klin" "${CMAKE_INSTALL_PREFIX}")
    file(RELATIVE_PATH _klin_pc_up
        "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig" "${CMAKE_INSTALL_PREFIX}")
    file(RELATIVE_PATH _klin_rel_libdir
        "${CMAKE_INSTALL_PREFIX}" "${CMAKE_INSTALL_FULL_LIBDIR}")
    file(RELATIVE_PATH _klin_rel_includedir
        "${CMAKE_INSTALL_PREFIX}" "${CMAKE_INSTALL_FULL_INCLUDEDIR}")

    configure_file(cmake/KlinConfig.cmake.in
        "${CMAKE_BINARY_DIR}/KlinConfig.cmake" @ONLY)
    write_basic_package_version_file("${CMAKE_BINARY_DIR}/KlinConfigVersion.cmake"
        VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
    install(FILES "${CMAKE_BINARY_DIR}/KlinConfig.cmake"
        "${CMAKE_BINARY_DIR}/KlinConfigVersion.cmake"
        DESTINATION "${_klin_cmakedir}")

    set(_klin_pc_requires "")
    if(KLIN_WITH_OPENSSL)
        list(APPEND _klin_pc_requires openssl)
    endif()
    if(KLIN_WITH_ZLIB)
        list(APPEND _klin_pc_requires zlib)
    endif()
    string(REPLACE ";" ", " _klin_pc_requires "${_klin_pc_requires}")
    list(TRANSFORM _klin_lib_names PREPEND "-l" OUTPUT_VARIABLE _klin_pc_libs)
    string(REPLACE ";" " " _klin_pc_libs "${_klin_pc_libs}")
    # GNU-style linkers need the cyclic archives grouped (Apple's rescans)
    if(NOT APPLE AND (CMAKE_C_LINK_GROUP_USING_RESCAN_SUPPORTED
            OR CMAKE_LINK_GROUP_USING_RESCAN_SUPPORTED))
        set(_klin_pc_libs "-Wl,--start-group ${_klin_pc_libs} -Wl,--end-group")
    endif()
    configure_file(cmake/klin.pc.in "${CMAKE_BINARY_DIR}/klin.pc" @ONLY)
    install(FILES "${CMAKE_BINARY_DIR}/klin.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
endif()

# ---------------------------------------------------------------------------
# Unit tests (KLIN_BUILD_TESTS=ON; ctest -L unit): the real libraries, no
# stubs (test/regressions.c covers extracted functions on any platform)
# ---------------------------------------------------------------------------
if(KLIN_BUILD_TESTS AND UNIX)
    enable_testing()
    add_executable(klin_unit_tests test/unit/unit_tests.c)
    klin_link_group(_unit_libs ${_klind_libs} klin_trans)
    target_link_libraries(klin_unit_tests PRIVATE klin_settings ${_unit_libs}
        ${KLIN_SYSTEM_LIBS})
    add_test(NAME unit COMMAND klin_unit_tests)
    set_tests_properties(unit PROPERTIES LABELS unit TIMEOUT 60)
endif()
