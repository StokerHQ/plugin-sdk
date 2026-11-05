# Stoker plugin SDK

Everything a Stoker plugin is built against and published with, in one place, so that a plugin's own repository
holds only its own code and one pinned version of this SDK.

| Part | What it is |
|---|---|
| `native/` | The C/C++ SDK for **hook plugins** and **integration packages**: `stoker/hook_plugin.h` (the hook ABI and `STOKER_PLUGIN_MANIFEST`), `stoker/plugin_support.h` (the ABI check, logging, options), a CMake package, MSBuild props, a cl/rc helper, and an example. [`native/HOOK-PLUGINS.md`](native/HOOK-PLUGINS.md) is the hook plugin guide. |
| `dotnet/StokerHQ.PluginRegistry` | NuGet `StokerHQ.PluginRegistry`: plugin registries in code — the statement a publisher signs, publisher and registry signatures, the checks an instance makes, the compiled index and its signed timestamp, and the reader for a hook plugin's manifest. |
| `dotnet/StokerHQ.PluginRegistry.Tool` | The .NET tool `StokerHQ.PluginRegistry.Tool`, command `stoker-registry`: keys, signed version entries, checking, compiling and signing a registry, and fetching this SDK. |
| `.github/workflows/` | This SDK's own CI, and **reusable workflows** a plugin repository calls: `build-hook-plugin.yml`, `check-release.yml`. |
| `scripts/` | `fetch-sdk.ps1` / `fetch-sdk.sh` (what a build runs to get the SDK it pins), `Build-Release.ps1` (a release). |
| `examples/plugin-repo/` | What a plugin repository adds: `stoker-plugin.yaml`, a ten-line workflow, a Renovate config. |

Licensed under the GNU Affero General Public License, version 3 or later (`AGPL-3.0-or-later`).

## Versions

- **The SDK** is versioned as a whole, `native/sdk.json`'s `version` (semver): a release `v<version>` carries the
  native zip and the two NuGet packages of that number.
- **The hook ABI** (`STOKER_HOOK_PLUGIN_ABI`, `sdk.json`'s `hookAbi`) changes on its own and rarely: a plugin built
  against ABI 1 loads under every bootstrap that speaks ABI 1, whichever SDK release built it. A new SDK release that
  keeps the ABI is a drop-in.
- An SDK major version changes when something a plugin's build depends on changes incompatibly: a header removed, a
  CMake target renamed.

## A plugin repository

A plugin repository holds its source and **`stoker-plugin.yaml`**, which pins this SDK by version and SHA-256 (the
format is [`plugin-project.schema.json`](https://schemas.stokerhq.app/plugins/v1/plugin-project.schema.json)):

```yaml
# yaml-language-server: $schema=https://schemas.stokerhq.app/plugins/v1/plugin-project.schema.json
schemaVersion: "1.0"
key: org.example.widescreen-fix
kind: hook
sdk:
  version: "1.0.1"
  sha256: "<the SHA-256 the SDK release names>"
targets:
  - { os: windows, architecture: x64, source: hook-plugin/widescreen_fix.cpp, name: widescreen_fix }
  - { os: windows, architecture: x86, source: hook-plugin/widescreen_fix.cpp, name: widescreen_fix }
```

Its build gets the SDK with `stoker-registry sdk` (or `scripts/fetch-sdk.ps1`/`.sh` from this repository), which
downloads the pinned release once, checks its SHA-256 and prints the folder to build against. Nothing of the SDK is
copied into the plugin's repository. Its CI is ten lines that call this repository's reusable workflow at a tag
(`examples/plugin-repo/.github/workflows/build.yml`), and Renovate (`examples/plugin-repo/renovate.json`) opens a pull
request when a new SDK release is out — bumping the version and the hash together.

`STOKER_PLUGIN_SDK` points a build at a local SDK instead — this repository's `native/` folder or a zip from
`scripts/Build-Release.ps1` — to build against an SDK change before it is released.

## The tool

```powershell
dotnet tool install -g StokerHQ.PluginRegistry.Tool
stoker-registry --help
```

| Command | Does |
|---|---|
| `keygen --out <key.pem>` | A new ECDSA P-256 key (encrypted PKCS#8 PEM); prints the public key as `registry.yaml` takes it. |
| `version …` | Writes a signed `<version>.yaml` for a release: files by size, SHA-256, BLAKE3 and asset URL; for a hook plugin, `abi`, `hosts`, `manifestSha256` and `config` read from the files' own manifest. |
| `check <registry> [--download]` | What an instance checks; `--download` also fetches every asset and compares it, the hook manifest included. |
| `compile`, `sign`, `verify-index` | The compiled index, its signed timestamp, and checking both as an instance does. |
| `sdk [--project stoker-plugin.yaml]` | Puts the pinned SDK into the cache and prints its folder. |

The registry format itself is in [StokerHQ/schemas](https://github.com/StokerHQ/schemas) (`plugins/v1`).

## Publishing a plugin version

1. Bump the version in the plugin's manifest; build every target from one commit.
2. Tag the commit (`v<version>` in a one-plugin repository, `<key>/<version>` in one of several) and create a release
   with the files as assets.
3. `stoker-registry version --key publisher.pem --publisher <id> --plugin <key> --version <v> --kind <kind>
   --repository <repo URL> --tag <tag> --commit <sha> --file <os> <arch> <path> <asset URL> … --out
   plugins/<key>` in a checkout of the registry, then `stoker-registry check . --download`, and open a pull request.

An administrator approves every version on their own instance before anything runs; a registry only makes a plugin
findable and checkable.

## Releasing the SDK

```powershell
./scripts/Build-Release.ps1           # dist/stoker-plugin-sdk-<version>.zip (+ .sha256) and dist/nuget/*.nupkg
```

Tag `v<version>`, create the release with the zip and its `.sha256`, and push the two packages to nuget.org
(`dotnet nuget push dist/nuget/*.nupkg --source https://api.nuget.org/v3/index.json --api-key <key>`). The zip is
reproducible: the same sources give the same SHA-256.
