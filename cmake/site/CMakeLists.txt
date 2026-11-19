# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
# Embedded site library for klind, built as an external project of the main
# Klin build once the 'klin' tool exists. This replaces site/Makefile and
# the autogen.mk/autogen.dps fragments with the autogen.cmake page list that
# 'klin -c import' writes.
#
# Cache inputs (set by the parent build):
#   KLIN_TOOL          path to the built klin tool
#   KLIN_SITE_DIR      site directory to embed (empty: no pages)
#   KLIN_IMPORT_ARGS   extra 'klin -c import' options (-z, -Z, -x, -e, -k)
#   KLIN_SITE_INCLUDE_DIRS, KLIN_SITE_DEFINITIONS, KLIN_SITE_OPTIONS
#   KLIN_SITE_OUTPUT   full path of the libsite archive to produce
cmake_minimum_required(VERSION 3.24)
project(klin_site C)

if(NOT EXISTS "${KLIN_TOOL}")
    message(FATAL_ERROR "klin tool not found: '${KLIN_TOOL}'")
endif()

set(_import_dir "${CMAKE_CURRENT_BINARY_DIR}/import")

# CMake's Makefile generators escape spaces in dependency paths as "\ ",
# which GNU make understands but BSD make does not.
set(_spaces_unsupported FALSE)
if(CMAKE_GENERATOR MATCHES "Makefiles")
    execute_process(COMMAND "${CMAKE_MAKE_PROGRAM}" --version
        OUTPUT_VARIABLE _make_version ERROR_QUIET)
    if(NOT _make_version MATCHES "GNU Make")
        set(_spaces_unsupported TRUE)
    endif()
endif()
file(MAKE_DIRECTORY "${_import_dir}")
set(_pages "")

if(KLIN_SITE_DIR)
    get_filename_component(_site "${KLIN_SITE_DIR}" ABSOLUTE)
    if(NOT IS_DIRECTORY "${_site}")
        message(FATAL_ERROR "KLIN_SITE_DIR is not a directory: '${_site}'")
    endif()

    # Re-run the import whenever a site file is added or removed, or the
    # klin tool changes (content edits are handled per page below).
    # FOLLOW_SYMLINKS: 'klin -c import' follows them too
    file(GLOB_RECURSE _site_files CONFIGURE_DEPENDS FOLLOW_SYMLINKS "${_site}/*")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${KLIN_TOOL}")

    execute_process(
        COMMAND "${KLIN_TOOL}" -c import ${KLIN_IMPORT_ARGS} "${_site}"
        WORKING_DIRECTORY "${_import_dir}"
        RESULT_VARIABLE _rc
        OUTPUT_VARIABLE _out
        ERROR_VARIABLE _out)
    if(_rc)
        message(FATAL_ERROR "klin -c import failed (${_rc}):\n${_out}")
    endif()
    string(STRIP "${_out}" _out)
    message(STATUS "Klin site: ${_out}")

    # klin_site_page(md5 ext file uri is_script compress encrypt key_file)
    function(klin_site_page md5 ext file uri is_script zip enc key)
        if(ext STREQUAL "cc")
            message(FATAL_ERROR "C++ page '${uri}' is not supported by this build")
        endif()
        # ';' separates CMake list items, so it cannot be passed through.
        # 'file', 'uri' and 'key' are only ever passed as quoted arguments
        # (never stored in a list, where '[' or ']' would change splitting).
        if(file MATCHES ";")
            message(FATAL_ERROR "Site file names containing ';' are not supported: '${uri}'")
        endif()
        if(key MATCHES ";")
            message(FATAL_ERROR "Key file paths containing ';' are not supported")
        endif()
        if(_spaces_unsupported AND ("${file}${key}${CMAKE_CURRENT_BINARY_DIR}" MATCHES " "))
            message(FATAL_ERROR "'${file}': paths containing spaces need Ninja or "
                "GNU make; ${CMAKE_MAKE_PROGRAM} cannot handle them in dependencies")
        endif()
        set(_out "${CMAKE_CURRENT_BINARY_DIR}/pg_${md5}.${ext}")
        set(_outputs "${_out}")
        set(_opts "")       # build-generated paths and flags only
        set(_depfile "")
        if(is_script)
            list(APPEND _opts -d "${_out}.kld")
            list(APPEND _outputs "${_out}.kld")
            set(_depfile DEPFILE "${_out}.kld")
        endif()
        if(zip)
            list(APPEND _opts -z)
        endif()
        if(enc)
            list(APPEND _opts -E)
        endif()
        # the extra leading '/' of -u is stripped by klin (it guards against
        # MSYS path conversion)
        if(enc AND key)
            # a new key must re-encrypt the page, so it is a dependency
            get_filename_component(key "${key}" ABSOLUTE BASE_DIR "${_import_dir}")
            add_custom_command(OUTPUT ${_outputs}
                COMMAND "${KLIN_TOOL}" -c translate -i "${file}" -o "${_out}"
                    ${_opts} -k "${key}" -u "/${uri}"
                DEPENDS "${file}" "${KLIN_TOOL}" "${key}"
                ${_depfile}
                WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
                COMMENT "Translating ${uri}"
                VERBATIM)
        else()
            add_custom_command(OUTPUT ${_outputs}
                COMMAND "${KLIN_TOOL}" -c translate -i "${file}" -o "${_out}"
                    ${_opts} -u "/${uri}"
                DEPENDS "${file}" "${KLIN_TOOL}"
                ${_depfile}
                WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
                COMMENT "Translating ${uri}"
                VERBATIM)
        endif()
        set(_pages ${_pages} "${_out}" PARENT_SCOPE)
    endfunction()

    include("${_import_dir}/autogen.cmake")
    set(_register "${_import_dir}/register.c")
else()
    set(_register "${CMAKE_CURRENT_LIST_DIR}/../../site/register-def.c")
endif()

add_library(site STATIC "${_register}" ${_pages})
get_filename_component(_outdir "${KLIN_SITE_OUTPUT}" DIRECTORY)
get_filename_component(_outname "${KLIN_SITE_OUTPUT}" NAME_WE)
string(REGEX REPLACE "^${CMAKE_STATIC_LIBRARY_PREFIX}" "" _outname "${_outname}")
set_target_properties(site PROPERTIES
    OUTPUT_NAME "${_outname}"
    ARCHIVE_OUTPUT_DIRECTORY "${_outdir}")
foreach(_cfg IN LISTS CMAKE_CONFIGURATION_TYPES)
    string(TOUPPER "${_cfg}" _cfg)
    set_target_properties(site PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_${_cfg} "${_outdir}")
endforeach()
target_include_directories(site PRIVATE ${KLIN_SITE_INCLUDE_DIRS})
target_compile_definitions(site PRIVATE ${KLIN_SITE_DEFINITIONS})
target_compile_options(site PRIVATE ${KLIN_SITE_OPTIONS})
