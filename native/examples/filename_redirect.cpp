// The SDK's build files define this; a bare compiler command line may not.
#ifndef STOKER_HOOK_PLUGIN_BUILD
#define STOKER_HOOK_PLUGIN_BUILD
#endif
#include "stoker/hook_plugin.h"

// What the Stoker server reads from this DLL without running it: which plugin and version the file
// is, and the options form an administrator fills in when assigning it to a game. Build the x86 and
// x64 DLLs from this same source so both carry the identical manifest; bump "version" whenever the
// code or the options change.
STOKER_PLUGIN_MANIFEST(R"json({
  "manifestVersion": 1,
  "id": "app.stokerhq.example.filename-redirect",
  "name": "CryptQueryObject filename redirect",
  "type": "hook",
  "version": "1.0.0",
  "abi": 1,
  "description": "Makes CryptQueryObject check a different file in the same folder, for games that verify a signature on a file Stoker replaced.",
  "hosts": ["steamworks", "ubisoft", "galaxy"],
  "config": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "match": {
        "type": "string",
        "title": "File the game checks",
        "description": "File name only, no folder. Compared without regard to case.",
        "default": "a.dll",
        "minLength": 1,
        "pattern": "^[^\\\\/:]+$",
        "examples": ["steam_api64.dll"]
      },
      "replace": {
        "type": "string",
        "title": "File to check instead",
        "description": "Looked up in the same folder as the original. Usually the untouched copy the install kept.",
        "default": "b.dll",
        "minLength": 1,
        "pattern": "^[^\\\\/:]+$",
        "examples": ["steam_api64.original.dll"]
      }
    }
  }
})json");

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <cwchar>

namespace {
    const stoker_hook_host_v1* g_host = nullptr;
    wchar_t g_match[256] = L"a.dll", g_replace[256] = L"b.dll";
    using Query = BOOL (WINAPI*)(DWORD, const void*, DWORD, DWORD, DWORD, DWORD*, DWORD*, DWORD*, HCERTSTORE*, HCRYPTMSG*, const void**);
    Query g_real = nullptr;

    std::string Utf8(const std::wstring& text) {
        const int count = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        std::string result(static_cast<size_t>(count), '\0');
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), count, nullptr, nullptr);
        return result;
    }
    bool ReadPath(const wchar_t* path, wchar_t* output) {
        __try { for (size_t i = 0; i < 32768; ++i) { output[i] = path[i]; if (!output[i]) return true; } }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        return false;
    }
    BOOL WINAPI HookedQuery(DWORD kind, const void* object, DWORD content, DWORD format, DWORD flags,
        DWORD* encoding, DWORD* contentType, DWORD* formatType, HCERTSTORE* store, HCRYPTMSG* message, const void** context) {
        const DWORD previousError = GetLastError();
        const void* originalObject = object;
        // Per-call storage survives the original call. There is no shared static redirect buffer
        // for another thread to overwrite, and a blob is never read as a string.
        std::wstring redirected;
        try {
            if (kind == CERT_QUERY_OBJECT_FILE && object) {
                wchar_t buffer[32768];
                if (ReadPath(static_cast<const wchar_t*>(object), buffer)) {
                    const std::wstring original(buffer);
                    const auto slash = original.find_last_of(L"\\/");
                    const auto name = slash == std::wstring::npos ? 0 : slash + 1;
                    if (CompareStringOrdinal(original.c_str() + name, -1, g_match, -1, TRUE) == CSTR_EQUAL) {
                        redirected = original.substr(0, name) + g_replace;
                        const auto line = "Redirected: " + Utf8(original) + " -> " + Utf8(redirected);
                        g_host->log(g_host->user, line.c_str());
                        object = redirected.c_str();
                    }
                }
            }
        } catch (...) { object = originalObject; }
        SetLastError(previousError);
        return g_real(kind, object, content, format, flags, encoding, contentType, formatType, store, message, context);
    }
    bool Option(const char* name, wchar_t* output) {
        char value[1024];
        const int result = g_host->config_string(g_host->user, name, value, sizeof value);
        if (result == STOKER_HOOK_NOT_FOUND) return true;
        if (result != STOKER_HOOK_OK || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, output, 256)) return false;
        return output[0] && !wcspbrk(output, L"\\/:") && wcscmp(output, L".") && wcscmp(output, L"..");
    }
}
#endif

STOKER_HOOK_PLUGIN_ENTRY int STOKER_HOOK_CALL stoker_hook_plugin_init(const stoker_hook_host_v1* host) {
    // MIN_SIZE rather than sizeof: an older bootstrap in a game folder has a shorter host structure.
    if (!host || host->abi_version != STOKER_HOOK_PLUGIN_ABI || host->struct_size < STOKER_HOOK_HOST_V1_MIN_SIZE) return STOKER_HOOK_UNSUPPORTED;
#ifdef _WIN32
    try {
        g_host = host;
        if (!Option("match", g_match) || !Option("replace", g_replace)) return STOKER_HOOK_INVALID_ARGUMENT;
        host->log(host->user, "Registering CryptQueryObject filename redirect");
        return host->hook_export(host->user, "crypt32.dll", "CryptQueryObject", reinterpret_cast<void*>(&HookedQuery), reinterpret_cast<void**>(&g_real));
    } catch (...) { return STOKER_HOOK_ERROR; }
#else
    host->log(host->user, "CryptQueryObject is a Windows API");
    return STOKER_HOOK_UNSUPPORTED;
#endif
}
