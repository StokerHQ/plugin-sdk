# Hook plugins

Write ordinary C/C++ detours, compile them for each platform, and drop the files on the Stoker admin
page **Plugins**. Then add the plugin to a game — or to one version of it — on that game's
**Fixes → Plugins** section, fill in its options, Save, Install/Verify, and restart the game.
The plugin initializes before the game's first ordinary SDK call.

## The manifest

Every plugin declares itself once, with `STOKER_PLUGIN_MANIFEST` from `stoker/hook_plugin.h`. The
server reads it from the compiled file without running it: which plugin and version the file is, and
the options form an administrator fills in.

```cpp
STOKER_PLUGIN_MANIFEST(R"json({
  "manifestVersion": 1,
  "id": "org.example.my-plugin",
  "name": "My plugin",
  "type": "hook",
  "version": "1.0.0",
  "abi": 1,
  "description": "What it does, in a sentence.",
  "hosts": ["steamworks", "ubisoft", "galaxy"],
  "config": { "type": "object", "properties": { … } }
})json");
```

- `id` — lower-case reverse-DNS, the plugin's identity across versions. `legacy.…` is reserved.
- `version` — `major.minor.patch` with an optional `-prerelease`. **Bump it whenever the code or the
  options change**: a version is immutable, and a different binary for a platform it already has is
  refused.
- Build every OS and architecture of a version **from the same source**, so all carry the byte-identical
  manifest — that is how they join one version, and why one options form is right for all of them.
- `hosts` — the bootstraps that may load it; omit for all three.
- `abi` — `1`, the value of `STOKER_HOOK_PLUGIN_ABI`.

### Options (`config`)

A small subset of JSON Schema. Anything outside it is refused at upload, with the reason.

| Kind | Write | Read in the plugin |
|---|---|---|
| text | `{ "type": "string" }` | `config_string` |
| whole number | `{ "type": "integer" }` | `config_int64` |
| number | `{ "type": "number" }` | `config_number` |
| on/off | `{ "type": "boolean" }` | `config_bool` |
| one of a list | `{ "enum": ["fast", "safe"] }` | `config_string` |
| list | `{ "type": "array", "items": { "type": "string" } }` | parse `config_json_utf8` |
| group | `{ "type": "object", "properties": { … } }` (one level) | parse `config_json_utf8` |

On any option: `title` (the label), **`description`** (shown under the field — say what it does, what a
sensible value looks like, and what happens when it is left alone), `default`, and `examples` (the
first becomes the empty input's placeholder). On text: `minLength`, `maxLength`, `pattern` (ECMAScript),
and `"x-stoker-widget": "multiline" | "path" | "hex"`. On numbers: `minimum`, `maximum`. On lists:
`minItems`, `maxItems`. `required` lists the options that must be given; `additionalProperties` may
only be `false`. At most 64 options; the saved options must fit in 4 KiB.

The server checks every saved configuration against this and fills in defaults, so the plugin
receives defaults it did not have to know about. There is no secret field: options are written in
plain text beside the game.

## The entry point

The single export is `int __cdecl stoker_hook_plugin_init(const stoker_hook_host_v1*)`. Define
`STOKER_HOOK_PLUGIN_BUILD` before including the header; it handles the undecorated x86 export. Check
`abi_version`, and check `struct_size` against `STOKER_HOOK_HOST_V1_MIN_SIZE` — **not** `sizeof` — so
the plugin still loads under an older bootstrap in a game folder. Call the typed getters only when
`STOKER_HOOK_HAS(host, config_int64)` (and so on) says they are there. Return `STOKER_HOOK_OK` after
registering hooks; other results discard that initializer's registrations.

The host provides logging, named-export and raw-address detour registration, and the option getters.
It owns MinHook, loads/retains target modules, and writes original function pointers before enabling
detours. `original` storage must be aligned and remain valid for the process lifetime. Register only
during initialization on the host worker. Do not call originals in init: a target may not yet be
loaded. Logs and option reads may be used on any thread. Every other pointer and string in the host
structure belongs to the host and survives until process exit. Never free it or throw across the C
interface. DLLs remain loaded; there is no live reload or shutdown callback.

Keep DllMain/global constructors inert. Initialization and detours run in the **game process**;
native code is not sandboxed. The server inspects uploaded files and never executes them.

## Building

Windows, with Visual Studio 2022's C++ tools in the matching developer command prompt:

```powershell
msbuild hook_plugin.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild hook_plugin.vcxproj /p:Configuration=Release /p:Platform=Win32
# Your source, using this project's include path and static CRT:
msbuild hook_plugin.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PluginSource=my_hooks.cpp /p:PluginName=my_hooks
```

Outputs are `build/x64/<name>.dll` and `build/Win32/<name>.dll`. Use `/MT` and ship a self-contained
DLL; dependency bundles are not supported.

Linux (the bootstrap's Linux loader is still a stub, but a registry and the catalogue take the file):

```sh
g++ -std=c++20 -shared -fPIC -fvisibility=hidden -O2 -Iinclude -DSTOKER_HOOK_PLUGIN_BUILD my_hooks.cpp -o my_hooks.so
```

Drop all the files on the **Plugins** page at once; each says which version it joined. Repeating an
upload is harmless.

## The example

`examples/filename_redirect.cpp` implements a CryptQueryObject handler: file queries only, `match` to
`replace`, directory preserved, original arguments and output pointers forwarded. Its manifest declares
both options with titles, descriptions, defaults, examples and a plain-file-name pattern — a complete
model for your own.
