// What Stoker's own hook plugins share: the ABI check, logging, options, and the `process` option.
//
// Header-only and inline on purpose. The SDK has no dependency bundles - a plugin is one DLL - so a
// shared static library would have to be linked into each anyway, and a header keeps each plugin's
// build the SDK's own one-source build (build/Build-HookPlugin.ps1). Nothing here crosses the plugin
// boundary: the ABI is still exactly stoker/hook_plugin.h.

#pragma once

#ifndef STOKER_HOOK_PLUGIN_BUILD
#define STOKER_HOOK_PLUGIN_BUILD
#endif
#include "stoker/hook_plugin.h"

namespace stoker::plugin
{
    inline const stoker_hook_host_v1* g_host = nullptr;
    inline bool Accept(const stoker_hook_host_v1* host)
    {
        if (!host || host->abi_version != STOKER_HOOK_PLUGIN_ABI || host->struct_size < STOKER_HOOK_HOST_V1_MIN_SIZE) return false;
        g_host = host;
        return true;
    }
}

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>

namespace stoker::plugin
{
    /// printf-style into the owner bootstrap's log. Safe on any thread, as the host's log is; a
    /// line longer than 1 KiB is cut rather than allocated for.
    inline void Log(const char* format, ...) noexcept
    {
        if (!g_host) return;
        char line[1024];
        va_list arguments;
        va_start(arguments, format);
        std::vsnprintf(line, sizeof line, format, arguments);
        va_end(arguments);
        g_host->log(g_host->user, line);
    }

    enum class OptionRead { Present, Missing, Invalid };

    /// A top-level string option into `output`. Missing leaves `output` as it was, so a caller that
    /// filled it with a default keeps that default.
    inline OptionRead Option(const char* key, char* output, uint32_t capacity)
    {
        char value[1024];
        const int result = g_host->config_string(g_host->user, key, value, sizeof value);
        if (result == STOKER_HOOK_NOT_FOUND) return OptionRead::Missing;
        if (result != STOKER_HOOK_OK || std::strlen(value) + 1 > capacity) return OptionRead::Invalid;
        std::memcpy(output, value, std::strlen(value) + 1);
        return OptionRead::Present;
    }

    /// A bare file name: not empty, no directory, no drive, not `.` or `..`. Options that name a
    /// file are resolved against a folder the plugin chooses, never against one the options choose.
    inline bool PlainFileName(const char* name)
    {
        return name[0] && !std::strpbrk(name, "\\/:") && std::strcmp(name, ".") && std::strcmp(name, "..");
    }

    inline bool Wide(const char* utf8, wchar_t* output, int capacity)
    {
        return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, output, capacity) > 0;
    }

    inline const wchar_t* FileName(const wchar_t* path)
    {
        const wchar_t* name = path;
        for (const wchar_t* c = path; *c; ++c)
            if (*c == L'\\' || *c == L'/') name = c + 1;
        return name;
    }

    /// Whether `path` ends in the file name `name`, case-insensitively as Windows compares them.
    inline bool NamesFile(const wchar_t* path, const wchar_t* name)
    {
        return CompareStringOrdinal(FileName(path), -1, name, -1, TRUE) == CSTR_EQUAL;
    }

    /// The `process` option every Stoker plugin honours: the file name of the one executable the
    /// plugin acts in. Install delivers each selection to its applicable bootstrap sites, and a
    /// recipe pairs plugins that belong in different processes - the store launcher and the game it
    /// starts - so without this each would also run in the other. Absent means every process.
    ///
    /// Returns false only for an invalid option; `matches` says whether this process is the one.
    inline bool ForThisProcess(bool& matches)
    {
        char process[MAX_PATH] = "";
        const OptionRead read = Option("process", process, sizeof process);
        if (read == OptionRead::Invalid || (read == OptionRead::Present && !PlainFileName(process))) return false;
        if (read == OptionRead::Missing) { matches = true; return true; }

        wchar_t wanted[MAX_PATH], self[MAX_PATH * 2];
        const DWORD length = GetModuleFileNameW(nullptr, self, MAX_PATH * 2);
        if (!Wide(process, wanted, MAX_PATH) || length == 0 || length >= MAX_PATH * 2) return false;
        matches = NamesFile(self, wanted);
        if (!matches) Log("not %s; nothing to do in this process", process);
        return true;
    }
}
#endif
