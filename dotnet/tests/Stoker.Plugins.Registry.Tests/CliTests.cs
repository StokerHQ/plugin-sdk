using System.Security.Cryptography;
using Stoker.Plugins.Registry;
using Xunit;

namespace Stoker.Registry.Tests;

/// <summary>
/// <c>stoker-registry</c> as a publisher and a registry's owner run it: a signed version entry from release files, a
/// registry that checks, an index compiled, signed and verified — and a second compile raising the serial.
/// </summary>
public sealed class CliTests : IDisposable
{
    private readonly string _work = Path.Combine(Path.GetTempPath(), $"stoker-registry-tests-{Guid.NewGuid():N}");

    public CliTests() => Directory.CreateDirectory(_work);

    public void Dispose() => Directory.Delete(_work, recursive: true);

    [Fact]
    public async Task AVersionIsWrittenSigned_ChecksCompilesSignsAndVerifies()
    {
        using var publisherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var registryKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publisherPem = Path.Combine(_work, "publisher.pem");
        var registryPem = Path.Combine(_work, "registry.pem");
        await File.WriteAllTextAsync(publisherPem, publisherKey.ExportPkcs8PrivateKeyPem(), TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(registryPem, registryKey.ExportPkcs8PrivateKeyPem(), TestContext.Current.CancellationToken);

        var root = Path.Combine(_work, "registry");
        var plugin = Path.Combine(root, "plugins", "app.stokerhq.example");
        Directory.CreateDirectory(plugin);
        await File.WriteAllTextAsync(Path.Combine(root, "registry.yaml"), $"""
            schemaVersion: "1.0"
            name: test
            url: "https://plugins.example.com"
            key: "{RegistryKey.Of(registryKey).Base64}"
            publishers:
              - id: stokerhq
                name: "StokerHQ"
                publicKey: "{RegistryKey.Of(publisherKey).Base64}"
                namespaces: ["app.stokerhq."]
            policy: {"{"} refusedKinds: [unpacker] {"}"}
            """, TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(Path.Combine(plugin, "plugin.yaml"),
            "schemaVersion: \"1.0\"\nkey: app.stokerhq.example\nkind: hook\nname: \"Example\"\n", TestContext.Current.CancellationToken);
        var asset = Path.Combine(_work, "example.dll");
        var image = HookPluginPe.Create(manifest: HookPluginPe.Manifest("app.stokerhq.example", "1.0.0", """{"type":"object","properties":{"match":{"type":"string","title":"Match"}}}"""));
        await File.WriteAllBytesAsync(asset, image, TestContext.Current.CancellationToken);

        // A file whose manifest names another plugin is refused before anything is signed.
        Assert.Equal(1, await Cli.RunAsync(["version", "--key", publisherPem, "--publisher", "stokerhq", "--plugin", "app.stokerhq.other",
            "--version", "1.0.0", "--kind", "hook", "--repository", "https://example.com/stoker", "--tag", "app.stokerhq.other/1.0.0",
            "--commit", new string('a', 40), "--file", "windows", "x64", asset, "https://example.com/other.dll", "--out", plugin]));

        Assert.Equal(0, await Cli.RunAsync(["version", "--key", publisherPem, "--publisher", "stokerhq", "--plugin", "app.stokerhq.example",
            "--version", "1.0.0", "--kind", "hook", "--repository", "https://example.com/stoker", "--tag", "app.stokerhq.example/1.0.0",
            "--commit", new string('a', 40), "--file", "windows", "x64", asset, "https://example.com/stoker/releases/download/app.stokerhq.example/1.0.0/example.dll",
            "--out", plugin]));
        var written = await File.ReadAllTextAsync(Path.Combine(plugin, "1.0.0.yaml"), TestContext.Current.CancellationToken);
        // The hook fields come from the file's own manifest.
        Assert.Contains("abi: 1", written, StringComparison.Ordinal);
        Assert.Contains("hosts: [\"steamworks\", \"ubisoft\"]", written, StringComparison.Ordinal);
        Assert.Contains("manifestSha256: ", written, StringComparison.Ordinal);
        Assert.Contains("config: {\"type\":\"object\"", written, StringComparison.Ordinal);

        Assert.Equal(0, await Cli.RunAsync(["check", root]));

        var output = Path.Combine(_work, "site");
        Assert.Equal(0, await Cli.RunAsync(["compile", root, "--out", output]));
        Assert.Equal(1, RegistryCompiler.SerialOf(await File.ReadAllBytesAsync(Path.Combine(output, CompiledIndex.TimestampPath), TestContext.Current.CancellationToken)));
        Assert.Equal(1, await Cli.RunAsync(["verify-index", output, "--key", Path.Combine(root, "registry.yaml")]));

        Assert.Equal(0, await Cli.RunAsync(["sign", output, "--key", registryPem]));
        Assert.Equal(0, await Cli.RunAsync(["verify-index", output, "--key", Path.Combine(root, "registry.yaml")]));
        Assert.Equal(1, await Cli.RunAsync(["verify-index", output, "--key", Path.Combine(root, "registry.yaml"), "--held-serial", "2"]));

        Assert.Equal(0, await Cli.RunAsync(["compile", root, "--out", output]));
        Assert.Equal(2, RegistryCompiler.SerialOf(await File.ReadAllBytesAsync(Path.Combine(output, CompiledIndex.TimestampPath), TestContext.Current.CancellationToken)));
        Assert.False(File.Exists(Path.Combine(output, CompiledIndex.SignaturePath)));

        var yaml = await File.ReadAllTextAsync(Path.Combine(plugin, "1.0.0.yaml"), TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(Path.Combine(plugin, "1.0.0.yaml"), yaml.Replace($"size: {image.Length}", $"size: {image.Length + 1}", StringComparison.Ordinal), TestContext.Current.CancellationToken);
        Assert.Equal(1, await Cli.RunAsync(["check", root]));
    }

    [Fact]
    public async Task TheSdkIsFetchedOnce_CheckedByHash_AndALocalFolderIsTakenAsItIs()
    {
        var zipPath = Path.Combine(_work, "stoker-plugin-sdk-9.9.9.zip");
        using (var zip = System.IO.Compression.ZipFile.Open(zipPath, System.IO.Compression.ZipArchiveMode.Create))
        {
            var entry = zip.CreateEntry("sdk.json");
            await using var writer = new StreamWriter(entry.Open());
            await writer.WriteAsync("""{ "version": "9.9.9", "hookAbi": 1 }""");
        }
        var sha = FileHashes.Sha256(await File.ReadAllBytesAsync(zipPath, TestContext.Current.CancellationToken));
        var cache = Path.Combine(_work, "cache");

        var previous = Environment.GetEnvironmentVariable(Cli.LocalSdkVariable);
        try
        {
            Environment.SetEnvironmentVariable(Cli.LocalSdkVariable, zipPath);
            Assert.Equal(1, await Cli.RunAsync(["sdk", "--version", "9.9.9", "--sha256", new string('0', 64), "--cache", cache]));
            Assert.Equal(0, await Cli.RunAsync(["sdk", "--version", "9.9.9", "--sha256", sha, "--cache", cache]));
            var unpacked = Path.Combine(cache, $"9.9.9-{sha[..12]}");
            Assert.True(File.Exists(Path.Combine(unpacked, "sdk.json")));

            Environment.SetEnvironmentVariable(Cli.LocalSdkVariable, unpacked);
            Assert.Equal(0, await Cli.RunAsync(["sdk", "--version", "9.9.9", "--sha256", new string('0', 64)]));
        }
        finally
        {
            Environment.SetEnvironmentVariable(Cli.LocalSdkVariable, previous);
        }
    }}
