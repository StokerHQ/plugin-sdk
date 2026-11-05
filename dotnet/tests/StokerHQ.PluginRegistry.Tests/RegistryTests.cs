using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using StokerHQ.PluginRegistry;
using StokerHQ.PluginRegistry.Tool;
using Xunit;

namespace StokerHQ.PluginRegistry.Tests;

/// <summary>
/// Plugin registries (plugin-registry.md §5, §7): the signed version statement, signatures made elsewhere verifying here,
/// what a host refuses, and the compiled index with its signed timestamp.
/// </summary>
public sealed class RegistryTests
{
    private static string Fixtures => Path.Combine(AppContext.BaseDirectory, "Fixtures", "registry");

    private static RegistryTree ReadFixtures()
    {
        var problems = new List<string>();
        var tree = RegistryYaml.ReadTree(Fixtures, problems);
        Assert.Empty(problems);
        return Assert.IsType<RegistryTree>(tree);
    }

    [Fact]
    public void TheStatementIsTheSchemasText_FilesInOrdinalOrder()
    {
        var bytes = PluginVersionStatement.Build("org.example.widescreen-fix", "1.0.0", "hook",
        [
            new StatementFile("windows", "x86", "widescreen_fix_x86.dll", 39424, "E3E3", "E4E4"),
            new StatementFile("windows", "x64", "widescreen_fix_x64.dll", 48640, "e1e1", "e2e2"),
        ]);

        Assert.Equal(
            "stoker-plugin-v1\norg.example.widescreen-fix\n1.0.0\nhook\n" +
            "windows\tx64\twidescreen_fix_x64.dll\t48640\te1e1\te2e2\n" +
            "windows\tx86\twidescreen_fix_x86.dll\t39424\te3e3\te4e4\n",
            Encoding.UTF8.GetString(bytes));
    }

    [Fact]
    public void AFieldWithATabOrLineBreakIsRefused() =>
        Assert.Throws<ArgumentException>(() => PluginVersionStatement.Build("org.example.a", "1.0.0\n", "hook", []));

    [Fact]
    public void TheExamplesSignaturesMadeElsewhereVerify()
    {
        var tree = ReadFixtures();

        Assert.Equal(4, tree.Plugins.Count);
        Assert.All(tree.Plugins, p => Assert.Single(p.Versions));
        Assert.Empty(RegistryChecker.Check(tree));

        var publisher = Assert.Single(tree.Registry.Publishers);
        foreach (var version in tree.Plugins.SelectMany(p => p.Versions))
            Assert.True(RegistrySignature.Verify(publisher.PublicKey, version.Statement, version.Signature.Value), version.Key);
    }

    [Fact]
    public void ASignatureRoundTrips_AndAChangedFileHashIsRefused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var name = RegistryKey.Of(key);
        StatementFile[] files = [new("linux", "il", "a.dll", 10, new string('a', 64), new string('b', 64))];

        var signature = RegistrySignature.Sign(key, PluginVersionStatement.Build("org.example.a", "1.0.0", "server", files));

        Assert.True(RegistrySignature.Verify(name, PluginVersionStatement.Build("org.example.a", "1.0.0", "server", files), signature));
        StatementFile[] changed = [files[0] with { Sha256 = new string('c', 64) }];
        Assert.False(RegistrySignature.Verify(name, PluginVersionStatement.Build("org.example.a", "1.0.0", "server", changed), signature));
        Assert.False(RegistrySignature.Verify(name, PluginVersionStatement.Build("org.example.a", "1.0.1", "server", files), signature));
        Assert.False(RegistrySignature.Verify(name, PluginVersionStatement.Build("org.example.a", "1.0.0", "server", files), "not base64!"));
    }

    [Fact]
    public void AKeyParsesFromBase64AndPem_WithTheReleaseKeysId()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var name = RegistryKey.Of(key);

        Assert.Equal(name.KeyId, RegistryKey.Parse(name.Base64).KeyId);
        Assert.Equal(name.KeyId, RegistryKey.Parse(key.ExportSubjectPublicKeyInfoPem()).KeyId);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())[..8]), name.KeyId);
    }

    [Fact]
    public void AVersionOutsideItsPublishersNamespacesIsRefused()
    {
        var tree = ReadFixtures();
        var registry = tree.Registry with { Publishers = [tree.Registry.Publishers[0] with { Namespaces = ["net.other."] }] };

        var problems = RegistryChecker.Check(tree with { Registry = registry });

        Assert.Equal(4, problems.Count(p => p.Contains("owns none of the namespaces", StringComparison.Ordinal)));
    }

    [Fact]
    public void ThePolicyRefusesKindsAndIntegrationProviders()
    {
        var tree = ReadFixtures();
        var registry = tree.Registry with
        {
            Policy = new RegistryPolicy(new HashSet<string> { "server" }, new HashSet<string> { "gogGalaxy" }),
        };

        var problems = RegistryChecker.Check(tree with { Registry = registry });

        Assert.Contains(problems, p => p.Contains("refuses kind server", StringComparison.Ordinal));
        Assert.Contains(problems, p => p.Contains("refuses integrations for gogGalaxy", StringComparison.Ordinal));
    }

    [Fact]
    public void ATagOfAnotherShapeIsRefused()
    {
        Assert.True(RegistryChecker.IsTag("v1.0.0", "org.example.a", "1.0.0"));
        Assert.True(RegistryChecker.IsTag("org.example.a/1.0.0", "org.example.a", "1.0.0"));
        Assert.False(RegistryChecker.IsTag("1.0.0", "org.example.a", "1.0.0"));
        Assert.False(RegistryChecker.IsTag("org.example.b/1.0.0", "org.example.a", "1.0.0"));
    }

    [Fact]
    public void ANamespaceTwoPublishersClaimIsRefused()
    {
        var tree = ReadFixtures();
        var first = tree.Registry.Publishers[0];
        var registry = tree.Registry with { Publishers = [first, first with { Id = "someone-else", Namespaces = ["org.example.sub."] }] };

        Assert.Contains(RegistryChecker.Check(tree with { Registry = registry }), p => p.Contains("lies inside", StringComparison.Ordinal));
    }

    [Fact]
    public void CompilingIsDeterministic_AndEveryFileIsPinned()
    {
        var tree = ReadFixtures();
        var generated = new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);

        var a = RegistryCompiler.Compile(tree, 7, generated, generated.AddDays(30));
        var b = RegistryCompiler.Compile(tree, 7, generated, generated.AddDays(30));

        Assert.Equal(a.Files.Keys, b.Files.Keys);
        Assert.All(a.Files, f => Assert.Equal(f.Value, b.Files[f.Key]));
        Assert.Contains(CompiledIndex.PluginPath("org.example.widescreen-fix"), a.Files.Keys);
        Assert.DoesNotContain(a.Files.Where(f => f.Key.EndsWith(".json", StringComparison.Ordinal)), f => f.Value.Contains((byte)'\r'));

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var timestamp = a.Files[CompiledIndex.TimestampPath];
        var verified = RegistryTimestamp.Verify(timestamp, RegistryTimestamp.Sign(key, timestamp), RegistryKey.Of(key), 0, generated, out var refusal);
        Assert.Null(refusal);
        Assert.Equal(7, verified!.Serial);
        Assert.All(a.Files.Where(f => f.Key != CompiledIndex.TimestampPath), f => Assert.True(RegistryTimestamp.Matches(verified, f.Key, f.Value), f.Key));

        var document = JsonNode.Parse(a.Files[CompiledIndex.PluginPath("org.example.itch-import")])!;
        Assert.Equal(7, document["serial"]!.GetValue<long>());
        Assert.Null(document["plugin"]!["$schema"]);
    }

    [Fact]
    public void AnIndexOfAnotherKeyALowerSerialOrPastItsExpiryIsRefused()
    {
        var tree = ReadFixtures();
        var generated = new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);
        var timestamp = RegistryCompiler.Compile(tree, 5, generated, generated.AddDays(30)).Files[CompiledIndex.TimestampPath];
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = RegistryTimestamp.Sign(key, timestamp);

        Assert.NotNull(RegistryTimestamp.Verify(timestamp, signature, RegistryKey.Of(key), 5, generated, out _));
        Assert.Null(RegistryTimestamp.Verify(timestamp, signature, RegistryKey.Of(other), 0, generated, out var wrongKey));
        Assert.Contains("not signed", wrongKey);
        Assert.Null(RegistryTimestamp.Verify(timestamp, signature, RegistryKey.Of(key), 6, generated, out var rolledBack));
        Assert.Contains("rolled back", rolledBack);
        Assert.Null(RegistryTimestamp.Verify(timestamp, signature, RegistryKey.Of(key), 0, generated.AddDays(31), out var expired));
        Assert.Contains("expired", expired);

        var tampered = (byte[])timestamp.Clone();
        tampered[^3] ^= 1;
        Assert.Null(RegistryTimestamp.Verify(tampered, signature, RegistryKey.Of(key), 0, generated, out _));
    }

    [Fact]
    public void YamlMeansWhatJsonWould()
    {
        var json = RegistryYaml.Parse("a: no\nb: 2013-01-14\nc: 010\nd: 10\ne: \"10\"\nf: true\ng: ~\nh: 1.5\n");

        Assert.Equal("no", json["a"]!.GetValue<string>());
        Assert.Equal("2013-01-14", json["b"]!.GetValue<string>());
        Assert.Equal("010", json["c"]!.GetValue<string>());
        Assert.Equal(10, json["d"]!.GetValue<long>());
        Assert.Equal("10", json["e"]!.GetValue<string>());
        Assert.True(json["f"]!.GetValue<bool>());
        Assert.Null(json["g"]);
        Assert.Equal(1.5, json["h"]!.GetValue<double>());

        Assert.Throws<FormatException>(() => RegistryYaml.Parse("a: 1\na: 2\n"));
        Assert.Throws<FormatException>(() => RegistryYaml.Parse("1: a\n"));
    }
}
