# The Stoker plugin SDK for CMake: `find_package(StokerPluginSdk 1 CONFIG REQUIRED)` with this folder on
# CMAKE_PREFIX_PATH (the fetch scripts print it), or FetchContent of a release zip.
#
#   target_link_libraries(my_plugin PRIVATE StokerPluginSdk::hook)
#
# StokerPluginSdk::hook carries the include path and STOKER_HOOK_PLUGIN_BUILD; stoker_hook_plugin() adds a
# plugin target with the settings a plugin must have: one self-contained shared library, the static C runtime on
# Windows, hidden symbols on Linux so only the entry point is exported.

include_guard(GLOBAL)

get_filename_component(StokerPluginSdk_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
file(READ "${StokerPluginSdk_ROOT}/sdk.json" _stoker_sdk_json)
string(JSON StokerPluginSdk_VERSION GET "${_stoker_sdk_json}" version)
string(JSON StokerPluginSdk_HOOK_ABI GET "${_stoker_sdk_json}" hookAbi)

if(NOT TARGET StokerPluginSdk::hook)
  add_library(StokerPluginSdk::hook INTERFACE IMPORTED)
  set_target_properties(StokerPluginSdk::hook PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${StokerPluginSdk_ROOT}/include"
    INTERFACE_COMPILE_DEFINITIONS "STOKER_HOOK_PLUGIN_BUILD"
    INTERFACE_COMPILE_FEATURES "cxx_std_20")
endif()

# stoker_hook_plugin(<name> SOURCES <file>...): a hook plugin library named <name>.
function(stoker_hook_plugin name)
  cmake_parse_arguments(PLUGIN "" "" "SOURCES" ${ARGN})
  add_library(${name} SHARED ${PLUGIN_SOURCES})
  target_link_libraries(${name} PRIVATE StokerPluginSdk::hook)
  set_target_properties(${name} PROPERTIES PREFIX "" CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
  if(MSVC)
    set_property(TARGET ${name} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_compile_options(${name} PRIVATE /utf-8 /W4)
  endif()
endfunction()
