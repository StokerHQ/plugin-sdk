#ifndef STOKER_HOOK_PLUGIN_H
#define STOKER_HOOK_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define STOKER_HOOK_CALL __cdecl
#define STOKER_HOOK_EXPORT __declspec(dllexport)
#else
#define STOKER_HOOK_CALL
#define STOKER_HOOK_EXPORT __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
#define STOKER_HOOK_EXTERN extern "C"
#else
#define STOKER_HOOK_EXTERN extern
#endif
#define STOKER_HOOK_PLUGIN_ENTRY STOKER_HOOK_EXTERN STOKER_HOOK_EXPORT
#if defined(STOKER_HOOK_PLUGIN_BUILD) && defined(_MSC_VER) && defined(_M_IX86)
#pragma comment(linker, "/export:stoker_hook_plugin_init=_stoker_hook_plugin_init")
#endif

#define STOKER_HOOK_PLUGIN_ABI 1u
enum stoker_hook_result {
    STOKER_HOOK_OK = 0,
    STOKER_HOOK_ERROR = 1,
    STOKER_HOOK_CONFLICT = 2,
    STOKER_HOOK_UNSUPPORTED = 3,
    STOKER_HOOK_INVALID_ARGUMENT = 4,
    STOKER_HOOK_NOT_FOUND = 5,
    STOKER_HOOK_BUFFER_TOO_SMALL = 6
};

/* C only at this boundary. The host and strings live until process exit. A plugin must not free
   them, throw across callbacks, or perform hook/network work in DllMain/global constructors.
   Initialization runs once on the process hook worker before the first ordinary SDK call.
   log/config_string may be called on any thread. Hook registration is initialization-only.
   Registration copies names and queues a detour; original must point at plugin-owned, aligned,
   process-lifetime storage. The host fills it BEFORE enabling the detour, possibly after a later
   DLL load. Never call original from init. Targets and plugins stay loaded until process exit. */
typedef struct stoker_hook_host_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    void* user;
    const char* game_directory_utf8;
    const char* config_json_utf8;
    void (STOKER_HOOK_CALL *log)(void* user, const char* message_utf8);
    int (STOKER_HOOK_CALL *hook_export)(void* user, const char* module_utf8, const char* function,
                                      void* detour, void** original);
    int (STOKER_HOOK_CALL *hook_address)(void* user, void* target, void* detour, void** original);
    /* Reads a top-level JSON string option, including the terminating NUL, into caller storage. */
    int (STOKER_HOOK_CALL *config_string)(void* user, const char* key_utf8, char* output, uint32_t capacity);

    /* Appended after the first release; present when struct_size covers them (STOKER_HOOK_HAS).
       A bootstrap already in a game folder may predate them. Each reads a top-level option of its
       JSON type: STOKER_HOOK_NOT_FOUND when absent, STOKER_HOOK_INVALID_ARGUMENT for another type
       (config_int64 also for a number with a fraction or outside int64). config_bool writes 0/1. */
    int (STOKER_HOOK_CALL *config_int64)(void* user, const char* key_utf8, int64_t* output);
    int (STOKER_HOOK_CALL *config_bool)(void* user, const char* key_utf8, int* output);
    int (STOKER_HOOK_CALL *config_number)(void* user, const char* key_utf8, double* output);
} stoker_hook_host_v1;

/* True when the host structure is long enough to contain `member` — test before calling an
   appended callback: if (STOKER_HOOK_HAS(host, config_int64)) host->config_int64(...). */
#define STOKER_HOOK_HAS(host, member) \
    ((host)->struct_size >= offsetof(stoker_hook_host_v1, member) + sizeof((host)->member))

/* The size of the structure as first released, without the appended callbacks. Check
   struct_size against this, not sizeof, so the plugin still loads under an older bootstrap. */
#define STOKER_HOOK_HOST_V1_MIN_SIZE ((uint32_t)offsetof(stoker_hook_host_v1, config_int64))

/* The plugin's manifest: what the Stoker server reads from the uploaded file, without running it,
   to place the file in its catalogue and to build the configuration form. One per plugin, as a
   string literal of UTF-8 JSON (a raw string literal in C++):

     STOKER_PLUGIN_MANIFEST(R"json({
       "manifestVersion": 1, "id": "de.example.redirect", "name": "Filename redirect",
       "type": "hook", "version": "1.0.0", "abi": 1,
       "config": { "type": "object", "properties": {
         "match": { "type": "string", "title": "Match", "description": "The file name to redirect." } } }
     })json");

   Every file of one version — each OS and architecture — must carry the byte-identical manifest.
   The server reads the section named .stkmeta; the export only keeps the linker from dropping it.
   See README.md for the fields and the configuration schema the form supports. */
#ifdef __cplusplus
#define STOKER_PLUGIN_LINKAGE extern "C"
#else
#define STOKER_PLUGIN_LINKAGE
#endif
#if defined(_MSC_VER)
#pragma section(".stkmeta", read)
#define STOKER_PLUGIN_MANIFEST(json) \
    STOKER_PLUGIN_LINKAGE __declspec(allocate(".stkmeta")) __declspec(dllexport) const char stoker_plugin_manifest[] = json
#else
#define STOKER_PLUGIN_MANIFEST(json) \
    STOKER_PLUGIN_LINKAGE __attribute__((section(".stkmeta"), used, visibility("default"))) const char stoker_plugin_manifest[] = json
#endif

typedef int (STOKER_HOOK_CALL *stoker_hook_plugin_init_fn)(const stoker_hook_host_v1* host);
/* Export exactly: int __cdecl stoker_hook_plugin_init(const stoker_hook_host_v1* host).
   Return STOKER_HOOK_OK to retain registered hooks. Other results discard that init's requests.
   The host owns MinHook; a plugin must not initialize/uninitialize its own copy. */

#endif
