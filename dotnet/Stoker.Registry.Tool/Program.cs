using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Stoker.Plugins.Registry;
using Stoker.Registry;

return await Cli.RunAsync(args);

namespace Stoker.Registry
{
    /// <summary>
    /// <c>stoker-registry</c>: keys, signed version entries, checking a registry, and compiling and signing its index
    /// (memory-bank/design/plugin-registry.md §5, §7).
    /// </summary>
    public static class Cli
    {
        /// <summary>The environment variable a private key's passphrase is read from before asking.</summary>
        public const string PassphraseVariable = "STOKER_KEY_PASSPHRASE";

        /// <summary>Runs one command; the process's exit code.</summary>
        public static async Task<int> RunAsync(string[] args)
        {
            if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
            {
                PrintUsage();
                return args.Length == 0 ? 2 : 0;
            }

            try
            {
                return args[0] switch
                {
                    "keygen" => KeyGen(new Options(args[1..])),
                    "version" => Version(new Options(args[1..])),
                    "check" => await CheckAsync(new Options(args[1..])),
                    "compile" => Compile(new Options(args[1..])),
                    "sign" => Sign(new Options(args[1..])),
                    "verify-index" => VerifyIndex(new Options(args[1..])),
                    "sdk" => await SdkAsync(new Options(args[1..])),
                    _ => Unknown(args[0]),
                };
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or IOException or CryptographicException or InvalidOperationException or InvalidDataException)
            {
                Console.Error.WriteLine($"stoker-registry: {ex.Message}");
                return 1;
            }
        }

        private static int Unknown(string command)
        {
            Console.Error.WriteLine($"stoker-registry: no command {command}");
            PrintUsage();
            return 2;
        }

        /// <summary>The usage text; README.md's "stoker-registry" section says the same.</summary>
        public static void PrintUsage() => Console.WriteLine("""
            stoker-registry - plugin registries (memory-bank/design/plugin-registry.md)

              keygen --out <key.pem>
                  A new ECDSA P-256 key, written as encrypted PKCS#8 PEM; asks for its passphrase (or reads
                  STOKER_KEY_PASSPHRASE). Prints the public key as registry.yaml takes it, and its id.

              version --key <key.pem> --publisher <id> --plugin <key> --version <v> --kind <kind>
                      --repository <url> --tag <tag> --commit <sha>
                      --file <os> <architecture> <path> <url> [--file ...] [--out <folder>]
                  Writes <folder>/<version>.yaml: the release, the source, every file with its size, SHA-256,
                  BLAKE3 and URL, and the publisher's signature. For a hook plugin, abi, hosts, manifestSha256
                  and config come from the files' own manifest, which must be the same in every file. Other
                  kinds' fields (loader, integration, server) are added by hand; the files' hashes, which the
                  signature covers, are what an instance checks them against.

              check <registry root> [--download]
                  Every version signed by a publisher registry.yaml lists, inside that publisher's namespaces,
                  allowed by the policy, with a tag of the right shape. --download fetches every file from its
                  URL (then the mirrors) and compares size, SHA-256 and BLAKE3, and for a hook plugin the
                  manifest in the file with the entry's abi, hosts, manifestSha256 and config.

              compile <registry root> --out <folder> [--previous <folder>] [--expires-days <n>]
                  Writes <folder>/index/v1/: plugins.json.zst, plugins/<key>.json and timestamp.json, at the
                  previous index's serial plus one (the --previous folder's, else the --out folder's own, else 1),
                  current for n days (30). Refuses a registry check would refuse. Removes a stale signature.

              sign <folder> --key <key.pem>
                  Writes <folder>/index/v1/timestamp.json.sig after checking every pinned file.

              verify-index <folder> --key <public key | registry.yaml> [--held-serial <n>]
                  Checks the signature, the serial, the expiry and every pinned file, as a host does.

              sdk [--project <stoker-plugin.yaml>] [--version <v> --sha256 <hash>] [--cache <folder>]
                  Puts the plugin SDK a project pins into the cache (once), checks its SHA-256, and prints the
                  folder to build against. STOKER_PLUGIN_SDK names a local SDK folder, used as it is, or a local
                  zip, which must still match the pin.
            """);

        private static int KeyGen(Options options)
        {
            var path = options.Required("--out");
            if (File.Exists(path)) throw new IOException($"{path} already exists. A key is never overwritten: a registry may already list it.");

            var passphrase = Passphrase(confirm: true);
            if (passphrase.Length < 12) throw new ArgumentException("Use a passphrase of at least 12 characters: it is all that protects the key on disk.");

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000);
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            File.WriteAllText(path, key.ExportEncryptedPkcs8PrivateKeyPem(passphrase, pbe), Encoding.ASCII);

            var name = RegistryKey.Of(key);
            Console.WriteLine($"Wrote {path}. Keep it off any server and back it up.");
            Console.WriteLine($"public key: {name.Base64}");
            Console.WriteLine($"key id:     {name.KeyId}");
            return 0;
        }

        private static int Version(Options options)
        {
            var kind = options.Required("--kind");
            var plugin = options.Required("--plugin");
            var version = options.Required("--version");
            var tag = options.Required("--tag");
            if (!RegistryChecker.IsTag(tag, plugin, version)) throw new ArgumentException($"--tag is v{version} or {plugin}/{version}.");

            var files = new List<PluginVersionFile>();
            foreach (var spec in options.Groups("--file", 4))
            {
                var (os, architecture, path, url) = (spec[0], spec[1], spec[2], spec[3]);
                if (!url.StartsWith("https://", StringComparison.Ordinal)) throw new ArgumentException($"{url}: a file's URL is https.");
                var bytes = File.ReadAllBytes(path);
                files.Add(new PluginVersionFile(os, architecture, Path.GetFileName(path), bytes.LongLength,
                    Convert.ToHexStringLower(SHA256.HashData(bytes)), FileHashes.Blake3(bytes), url));
            }
            if (files.Count == 0) throw new ArgumentException("Name at least one --file <os> <architecture> <path> <url>.");

            // A hook plugin says what it is in its own manifest: the entry takes abi, hosts, manifestSha256 and config
            // from there, after checking every file carries the same manifest and is the file it is listed as.
            HookManifest? hook = null;
            if (kind == "hook")
            {
                foreach (var spec in options.Groups("--file", 4))
                {
                    var manifest = HookManifest.Read(File.ReadAllBytes(spec[2]));
                    if (manifest.Id != plugin || manifest.Version != version)
                        throw new ArgumentException($"{spec[2]}: its manifest is {manifest.Id} {manifest.Version}, not {plugin} {version}.");
                    if (manifest.Os != spec[0] || manifest.Architecture != spec[1])
                        throw new ArgumentException($"{spec[2]}: it is a {manifest.Os} {manifest.Architecture} library, not {spec[0]} {spec[1]}.");
                    if (hook is not null && manifest.ManifestSha256 != hook.ManifestSha256)
                        throw new ArgumentException($"{spec[2]}: its manifest differs from the other files'; build every file of a version from the same source.");
                    hook = manifest;
                }
            }

            var statement = PluginVersionStatement.Build(plugin, version, kind, files.Select(f => f.Statement));
            using var key = LoadKey(options.Required("--key"));
            var signature = RegistrySignature.Sign(key, statement);

            var yaml = new StringBuilder()
                .Append("# yaml-language-server: $schema=https://schemas.stokerhq.app/plugins/v1/version.schema.json\n")
                .Append("schemaVersion: \"1.0\"\n")
                .Append("key: ").Append(Quote(plugin)).Append('\n')
                .Append("version: ").Append(Quote(version)).Append('\n')
                .Append("kind: ").Append(Quote(kind)).Append('\n')
                .Append("release: { repository: ").Append(Quote(options.Required("--repository"))).Append(", tag: ").Append(Quote(tag)).Append(" }\n")
                .Append("source: { repository: ").Append(Quote(options.Value("--source-repository") ?? options.Required("--repository")))
                .Append(", commit: ").Append(Quote(options.Required("--commit"))).Append(" }\n")
                .Append("signature: { publisher: ").Append(Quote(options.Required("--publisher"))).Append(", algorithm: ")
                .Append(RegistrySignature.Algorithm).Append(", value: ").Append(Quote(signature)).Append(" }\n");
            if (hook is not null)
            {
                yaml.Append("abi: ").Append(hook.Abi.ToString(CultureInfo.InvariantCulture)).Append('\n');
                if (hook.Hosts.Count > 0) yaml.Append("hosts: [").Append(string.Join(", ", hook.Hosts.Select(Quote))).Append("]\n");
                yaml.Append("manifestSha256: ").Append(Quote(hook.ManifestSha256)).Append('\n');
                // JSON is YAML: the contract goes in as the manifest wrote it, every string quoted.
                if (hook.Config is { } config) yaml.Append("config: ").Append(config.ToJsonString(FlowJson)).Append('\n');
            }
            yaml.Append("files:\n");
            foreach (var file in files.OrderBy(f => $"{f.Os}\t{f.Architecture}\t{f.FileName}", StringComparer.Ordinal))
            {
                yaml.Append("  - os: ").Append(file.Os).Append('\n')
                    .Append("    architecture: ").Append(file.Architecture).Append('\n')
                    .Append("    fileName: ").Append(Quote(file.FileName)).Append('\n')
                    .Append("    size: ").Append(file.Size.ToString(CultureInfo.InvariantCulture)).Append('\n')
                    .Append("    sha256: ").Append(Quote(file.Sha256)).Append('\n')
                    .Append("    blake3: ").Append(Quote(file.Blake3)).Append('\n')
                    .Append("    url: ").Append(Quote(file.Url)).Append('\n');
            }

            var folder = options.Value("--out") ?? ".";
            Directory.CreateDirectory(folder);
            var output = Path.Combine(folder, $"{version}.yaml");
            if (File.Exists(output)) throw new IOException($"{output} already exists. A published version never changes; make a new one.");
            File.WriteAllText(output, yaml.ToString(), new UTF8Encoding(false));
            Console.WriteLine($"Wrote {output}, signed by {options.Required("--publisher")} (key {RegistryKey.Of(key).KeyId}).");
            return 0;
        }

        private static async Task<int> CheckAsync(Options options)
        {
            var root = options.Positional(0, "<registry root>");
            var problems = new List<string>();
            var tree = RegistryYaml.ReadTree(root, problems);
            if (tree is not null) problems.AddRange(RegistryChecker.Check(tree));

            if (tree is not null && options.Flag("--download"))
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("stoker-registry");
                foreach (var plugin in tree.Plugins)
                foreach (var version in plugin.Versions)
                foreach (var file in version.Files)
                {
                    var bytes = await DownloadAsync(http, file, tree.Registry.Mirrors);
                    var where = $"plugins/{plugin.Folder}/{version.Version}.yaml: {file.FileName}";
                    if (bytes is null) problems.Add($"{where}: neither {file.Url} nor any mirror served it");
                    else if (bytes.LongLength != file.Size) problems.Add($"{where}: {bytes.LongLength} bytes, not {file.Size}");
                    else if (Convert.ToHexStringLower(SHA256.HashData(bytes)) != file.Sha256.ToLowerInvariant()) problems.Add($"{where}: the SHA-256 differs");
                    else if (FileHashes.Blake3(bytes) != file.Blake3.ToLowerInvariant()) problems.Add($"{where}: the BLAKE3 differs");
                    else if (version.Kind == "hook")
                    {
                        try
                        {
                            problems.AddRange(HookManifest.Read(bytes).Differences(version, file).Select(d => $"{where}: {d}"));
                        }
                        catch (InvalidDataException ex)
                        {
                            problems.Add($"{where}: {ex.Message}");
                        }
                    }
                }
            }

            foreach (var problem in problems) Console.WriteLine(problem);
            var versions = tree?.Plugins.Sum(p => p.Versions.Count) ?? 0;
            Console.WriteLine($"{tree?.Plugins.Count ?? 0} plugins, {versions} versions, {problems.Count} problems");
            return problems.Count == 0 ? 0 : 1;
        }

        private static async Task<byte[]?> DownloadAsync(HttpClient http, PluginVersionFile file, IReadOnlyList<string> mirrors)
        {
            var sha = file.Sha256.ToLowerInvariant();
            foreach (var url in new[] { file.Url }.Concat(mirrors.Select(m => $"{m}/{sha[..2]}/{sha}")))
            {
                try
                {
                    var bytes = await http.GetByteArrayAsync(url);
                    if (Convert.ToHexStringLower(SHA256.HashData(bytes)) == sha || url == file.Url) return bytes;
                }
                catch (HttpRequestException)
                {
                }
            }
            return null;
        }

        private static int Compile(Options options)
        {
            var root = options.Positional(0, "<registry root>");
            var output = options.Required("--out");
            var problems = new List<string>();
            var tree = RegistryYaml.ReadTree(root, problems) ?? throw new InvalidOperationException(string.Join(Environment.NewLine, problems));
            problems.AddRange(RegistryChecker.Check(tree));
            if (problems.Count > 0) throw new InvalidOperationException("The registry has problems; nothing was compiled:" + Environment.NewLine + string.Join(Environment.NewLine, problems));

            var previous = options.Value("--previous") ?? output;
            var previousTimestamp = Path.Combine(previous, CompiledIndex.TimestampPath);
            var serial = File.Exists(previousTimestamp) ? RegistryCompiler.SerialOf(File.ReadAllBytes(previousTimestamp)) + 1 : 1;
            var days = int.Parse(options.Value("--expires-days") ?? "30", CultureInfo.InvariantCulture);
            if (days < 1) throw new ArgumentException("--expires-days is 1 or more.");

            var now = DateTimeOffset.UtcNow;
            now = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, now.Minute, now.Second, TimeSpan.Zero);
            var index = RegistryCompiler.Compile(tree, serial, now, now.AddDays(days));

            var indexRoot = Path.Combine(output, "index", "v1");
            if (Directory.Exists(indexRoot)) Directory.Delete(indexRoot, recursive: true);
            foreach (var (path, bytes) in index.Files)
            {
                var file = Path.Combine(output, path);
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                File.WriteAllBytes(file, bytes);
            }

            Console.WriteLine($"Compiled {tree.Plugins.Count} plugins at serial {serial} into {indexRoot}; current until {now.AddDays(days):u}. Sign it: stoker-registry sign {output} --key <registry key>");
            return 0;
        }

        private static int Sign(Options options)
        {
            var folder = options.Positional(0, "<folder>");
            var timestamp = File.ReadAllBytes(Path.Combine(folder, CompiledIndex.TimestampPath));
            using var key = LoadKey(options.Required("--key"));

            var name = RegistryKey.Of(key);
            var unsigned = RegistryTimestamp.Verify(timestamp, RegistrySignature.Sign(key, timestamp), name, 0, DateTimeOffset.UtcNow, out var refusal)
                ?? throw new InvalidOperationException(refusal);
            foreach (var problem in PinProblems(folder, unsigned)) throw new InvalidOperationException(problem);

            var signature = RegistryTimestamp.Sign(key, timestamp);
            File.WriteAllBytes(Path.Combine(folder, CompiledIndex.SignaturePath), RegistryTimestamp.SignatureFile(signature));
            Console.WriteLine($"Signed serial {unsigned.Serial} of {unsigned.Registry} with key {name.KeyId}.");
            return 0;
        }

        private static int VerifyIndex(Options options)
        {
            var folder = options.Positional(0, "<folder>");
            var keyText = options.Required("--key");
            var key = File.Exists(keyText) && Path.GetFileName(keyText) == "registry.yaml"
                ? RegistryDocument.From(RegistryYaml.Parse(File.ReadAllText(keyText))).Key
                : RegistryKey.Parse(File.Exists(keyText) ? File.ReadAllText(keyText) : keyText);
            var held = long.Parse(options.Value("--held-serial") ?? "0", CultureInfo.InvariantCulture);

            var timestamp = File.ReadAllBytes(Path.Combine(folder, CompiledIndex.TimestampPath));
            var signaturePath = Path.Combine(folder, CompiledIndex.SignaturePath);
            var signature = File.Exists(signaturePath) ? File.ReadAllText(signaturePath) : null;

            var verified = RegistryTimestamp.Verify(timestamp, signature, key, held, DateTimeOffset.UtcNow, out var refusal);
            if (verified is null)
            {
                Console.WriteLine(refusal);
                return 1;
            }

            var problems = PinProblems(folder, verified).ToList();
            foreach (var problem in problems) Console.WriteLine(problem);
            Console.WriteLine(problems.Count == 0
                ? $"{verified.Registry}: serial {verified.Serial}, signed by {key.KeyId}, current until {verified.Expires:u}, {verified.Pinned.Count} files as pinned."
                : $"{verified.Registry}: {problems.Count} files not as pinned.");
            return problems.Count == 0 ? 0 : 1;
        }

        private static IEnumerable<string> PinProblems(string folder, VerifiedTimestamp timestamp)
        {
            foreach (var path in timestamp.Pinned.Keys)
            {
                var file = Path.Combine(folder, path);
                if (!File.Exists(file)) yield return $"{path}: missing";
                else if (!RegistryTimestamp.Matches(timestamp, path, File.ReadAllBytes(file))) yield return $"{path}: not the file timestamp.json pins";
            }
        }

        private static ECDsa LoadKey(string path)
        {
            var pem = File.ReadAllText(path);
            return RegistrySignature.LoadPrivateKey(pem, RegistrySignature.IsEncrypted(pem) ? Passphrase(confirm: false) : []);
        }

        private static char[] Passphrase(bool confirm)
        {
            if (Environment.GetEnvironmentVariable(PassphraseVariable) is { Length: > 0 } fromEnvironment) return fromEnvironment.ToCharArray();
            if (Console.IsInputRedirected) throw new InvalidOperationException($"No passphrase: set {PassphraseVariable}, or run in a terminal.");

            var first = ReadHidden(confirm ? "Passphrase for the new key: " : "Passphrase: ");
            if (confirm && !first.AsSpan().SequenceEqual(ReadHidden("The same passphrase again: "))) throw new ArgumentException("The two passphrases differ. Nothing was written.");
            return first;
        }

        private static char[] ReadHidden(string prompt)
        {
            Console.Error.Write(prompt);
            var text = new List<char>();
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace) { if (text.Count > 0) text.RemoveAt(text.Count - 1); }
                else if (!char.IsControl(key.KeyChar)) text.Add(key.KeyChar);
            }
            Console.Error.WriteLine();
            return [.. text];
        }

        /// <summary>The environment variable naming a local SDK folder or zip a build uses instead of a download.</summary>
        public const string LocalSdkVariable = "STOKER_PLUGIN_SDK";

        private static async Task<int> SdkAsync(Options options)
        {
            var version = options.Value("--version");
            var sha256 = options.Value("--sha256");
            if (version is null || sha256 is null)
            {
                var project = options.Value("--project") ?? "stoker-plugin.yaml";
                if (!File.Exists(project)) throw new IOException($"No {project}, and no --version and --sha256.");
                var sdk = RegistryYaml.Parse(await File.ReadAllTextAsync(project))["sdk"] as JsonObject
                    ?? throw new FormatException($"{project} pins no sdk {{ version, sha256 }}.");
                version ??= sdk["version"]?.GetValue<string>() ?? throw new FormatException($"{project}: sdk.version is missing.");
                sha256 ??= sdk["sha256"]?.GetValue<string>() ?? throw new FormatException($"{project}: sdk.sha256 is missing.");
            }
            sha256 = sha256.ToLowerInvariant();
            if (sha256.Length != 64 || !sha256.All(Uri.IsHexDigit)) throw new FormatException("The SDK's SHA-256 is 64 hex digits.");

            var local = Environment.GetEnvironmentVariable(LocalSdkVariable);
            if (!string.IsNullOrEmpty(local) && Directory.Exists(local))
            {
                if (!File.Exists(Path.Combine(local, "sdk.json"))) throw new IOException($"{LocalSdkVariable} ({local}) holds no sdk.json.");
                Console.WriteLine(Path.GetFullPath(local));
                return 0;
            }

            var cache = options.Value("--cache") ?? DefaultSdkCache();
            var target = Path.Combine(cache, $"{version}-{sha256[..12]}");
            if (File.Exists(Path.Combine(target, "sdk.json")))
            {
                Console.WriteLine(target);
                return 0;
            }

            byte[] zip;
            if (!string.IsNullOrEmpty(local)) zip = await File.ReadAllBytesAsync(local);
            else
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("stoker-registry");
                zip = await http.GetByteArrayAsync($"https://github.com/StokerHQ/plugin-sdk/releases/download/v{version}/stoker-plugin-sdk-{version}.zip");
            }
            var actual = FileHashes.Sha256(zip);
            if (actual != sha256) throw new InvalidDataException($"stoker-plugin-sdk-{version}.zip has SHA-256 {actual}, not the pinned {sha256}.");

            Directory.CreateDirectory(cache);
            var staging = $"{target}.{Guid.NewGuid():N}";
            using (var archive = new System.IO.Compression.ZipArchive(new MemoryStream(zip)))
                System.IO.Compression.ZipFileExtensions.ExtractToDirectory(archive, staging);
            if (Directory.Exists(target)) Directory.Delete(staging, recursive: true);
            else Directory.Move(staging, target);
            Console.WriteLine(target);
            return 0;
        }

        private static string DefaultSdkCache()
        {
            if (OperatingSystem.IsWindows())
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StokerHQ", "plugin-sdk");
            var xdg = Environment.GetEnvironmentVariable("XDG_CACHE_HOME");
            return Path.Combine(string.IsNullOrEmpty(xdg) ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cache") : xdg, "stokerhq", "plugin-sdk");
        }

        private static string Quote(string value) => JsonValue.Create(value).ToJsonString();

        /// <summary>JSON as YAML takes it in flow style: non-ASCII text as itself rather than as escapes.</summary>
        private static readonly System.Text.Json.JsonSerializerOptions FlowJson = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    }

    /// <summary>A command's arguments: positionals, <c>--name value</c> options, flags, and groups of values after a repeated option.</summary>
    internal sealed class Options(string[] args)
    {
        public string Positional(int index, string what)
        {
            var positionals = new List<string>();
            for (var i = 0; i < args.Length; i++)
            {
                if (args[i].StartsWith("--", StringComparison.Ordinal))
                {
                    i += args[i] is "--download" ? 0 : args[i] == "--file" ? 4 : 1;
                    continue;
                }
                positionals.Add(args[i]);
            }
            return positionals.Count > index ? positionals[index] : throw new ArgumentException($"Name {what}.");
        }

        public string? Value(string name)
        {
            var at = Array.LastIndexOf(args, name);
            return at >= 0 && at + 1 < args.Length ? args[at + 1] : null;
        }

        public string Required(string name) => Value(name) ?? throw new ArgumentException($"{name} is required.");

        public bool Flag(string name) => args.Contains(name);

        public IEnumerable<string[]> Groups(string name, int count)
        {
            for (var i = 0; i < args.Length; i++)
            {
                if (args[i] != name) continue;
                if (i + count >= args.Length) throw new ArgumentException($"{name} takes {count} values.");
                yield return args[(i + 1)..(i + 1 + count)];
                i += count;
            }
        }
    }
}
