using System.Text.Json.Nodes;
using Stoker.Plugins.Registry;
using Xunit;

namespace Stoker.Registry.Tests;

/// <summary>A hook plugin's manifest read from its file, and compared with the version entry that lists it.</summary>
public sealed class HookManifestTests
{
    private static readonly string Config = """{"type":"object","properties":{"match":{"type":"string"}}}""";

    [Fact]
    public void Reads_the_manifest_and_what_the_file_is_from_a_PE()
    {
        var manifest = HookManifest.Read(HookPluginPe.Create(x64: true, manifest: HookPluginPe.Manifest("org.example.redirect", "1.2.0", Config)));

        Assert.Equal(("windows", "x64"), (manifest.Os, manifest.Architecture));
        Assert.Equal(("org.example.redirect", "1.2.0", "hook", 1), (manifest.Id, manifest.Version, manifest.Type, manifest.Abi));
        Assert.Equal(["steamworks", "ubisoft"], manifest.Hosts);
        Assert.Equal("string", manifest.Config!["properties"]!["match"]!["type"]!.GetValue<string>());
        Assert.Equal(64, manifest.ManifestSha256.Length);

        Assert.Equal("x86", HookManifest.Read(HookPluginPe.Create(x64: false, manifest: HookPluginPe.Manifest())).Architecture);
    }

    [Fact]
    public void A_file_without_a_manifest_is_refused()
    {
        Assert.Throws<InvalidDataException>(() => HookManifest.Read(HookPluginPe.Create()));
        Assert.Throws<InvalidDataException>(() => HookManifest.Read([1, 2, 3]));
    }

    [Fact]
    public void Differences_name_every_field_an_entry_gets_wrong()
    {
        var image = HookPluginPe.Create(manifest: HookPluginPe.Manifest("org.example.redirect", "1.2.0", Config));
        var manifest = HookManifest.Read(image);
        var file = new PluginVersionFile("windows", "x64", "redirect.dll", image.LongLength, FileHashes.Sha256(image), FileHashes.Blake3(image), "https://example.com/redirect.dll");

        JsonObject Entry(string manifestSha256, int abi, string[] hosts, string config) => new()
        {
            ["manifestSha256"] = manifestSha256,
            ["abi"] = abi,
            ["hosts"] = new JsonArray([.. hosts.Select(h => (JsonNode)h)]),
            ["config"] = JsonNode.Parse(config),
        };
        PluginVersionDocument Version(string key, string version, JsonObject json) =>
            new(key, version, "hook", new PluginRelease("https://example.com/redirect", $"v{version}"), new PluginVersionSignature("p", RegistrySignature.Algorithm, ""), [file], null, json);

        Assert.Empty(manifest.Differences(Version("org.example.redirect", "1.2.0", Entry(manifest.ManifestSha256, 1, ["ubisoft", "steamworks"], Config)), file));

        var wrong = manifest.Differences(Version("org.example.other", "1.3.0", Entry(new string('0', 64), 2, ["steamworks"], """{"type":"object"}""")), file);
        Assert.Equal(6, wrong.Count);
    }
}
