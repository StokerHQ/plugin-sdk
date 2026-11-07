using System.Net;
using System.Security.Cryptography;
using System.Text;
using StokerHQ.PluginRegistry;
using StokerHQ.PluginRegistry.Tool;
using Xunit;

namespace StokerHQ.PluginRegistry.Tests;

/// <summary>
/// A version entry's <c>notes</c> and <c>released</c>: written by <c>stoker-registry version</c> from a file or the
/// GitHub release, read back as YAML means them, and an entry the schema refuses — a hook version whose <c>abi</c>
/// ended up inside its notes — refused by <c>check</c>.
/// </summary>
[Collection(nameof(VersionNotesTests))]
public sealed class VersionNotesTests : IDisposable
{
    private const string Plugin = "app.stokerhq.example";

    // Everything that could end a block scalar early, or be read as something other than its text.
    private const string TrickyNotes =
        "\uFEFF\r\n   Indented first line: a colon, then more\r\n" +
        "key: value\r\n" +
        "abi: 2\r\n" +
        "# not a comment\r\n" +
        "'single' and \"double\" quotes, a { brace and a [ bracket\r\n" +
        "\tA tab first, and\ttabs inside\r\n" +
        "---\r\n" +
        "...\r\n" +
        "\r\n" +
        "\r\n" +
        "- item: with a colon #and a hash\r\n" +
        "  - nested item\r" +
        "an old Mac line end before, a line separator here\u2028abi: 3\r\n" +
        "a trailing-space line  \r\n" +
        "|\r\n" +
        "> last line, no line end";

    private const string NormalizedNotes =
        "   Indented first line: a colon, then more\n" +
        "key: value\n" +
        "abi: 2\n" +
        "# not a comment\n" +
        "'single' and \"double\" quotes, a { brace and a [ bracket\n" +
        "\tA tab first, and\ttabs inside\n" +
        "---\n" +
        "...\n" +
        "\n" +
        "\n" +
        "- item: with a colon #and a hash\n" +
        "  - nested item\n" +
        "an old Mac line end before, a line separator here\nabi: 3\n" +
        "a trailing-space line  \n" +
        "|\n" +
        "> last line, no line end";

    private readonly string _work = Path.Combine(Path.GetTempPath(), $"stoker-registry-notes-{Guid.NewGuid():N}");
    private readonly string _root;
    private readonly string _pluginFolder;
    private readonly string _publisherPem;
    private readonly string _asset;

    public VersionNotesTests()
    {
        _root = Path.Combine(_work, "registry");
        _pluginFolder = Path.Combine(_root, "plugins", Plugin);
        Directory.CreateDirectory(_pluginFolder);

        using var publisherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var registryKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _publisherPem = Path.Combine(_work, "publisher.pem");
        File.WriteAllText(_publisherPem, publisherKey.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(Path.Combine(_root, "registry.yaml"), $"""
            schemaVersion: "1.0"
            name: test
            url: "https://plugins.example.com"
            key: "{RegistryKey.Of(registryKey).Base64}"
            publishers:
              - id: stokerhq
                name: "StokerHQ"
                publicKey: "{RegistryKey.Of(publisherKey).Base64}"
                namespaces: ["app.stokerhq."]
            """);
        File.WriteAllText(Path.Combine(_pluginFolder, "plugin.yaml"), $"schemaVersion: \"1.0\"\nkey: {Plugin}\nkind: hook\nname: \"Example\"\n");
        _asset = Path.Combine(_work, "example.dll");
        File.WriteAllBytes(_asset, HookPluginPe.Create(manifest: HookPluginPe.Manifest(Plugin, "1.0.0", null)));
    }

    public void Dispose()
    {
        ReleaseNotes.Handler = null;
        Directory.Delete(_work, recursive: true);
    }

    private Task<int> Version(string repository, params string[] extra) => Cli.RunAsync([
        "version", "--key", _publisherPem, "--publisher", "stokerhq", "--plugin", Plugin, "--version", "1.0.0", "--kind", "hook",
        "--repository", repository, "--tag", "v1.0.0", "--commit", new string('a', 40),
        "--file", "windows", "x64", _asset, "https://example.com/example.dll", "--out", _pluginFolder, .. extra]);

    private string Entry => Path.Combine(_pluginFolder, "1.0.0.yaml");

    private List<string> Problems()
    {
        var problems = new List<string>();
        var tree = RegistryYaml.ReadTree(_root, problems);
        if (tree is not null) problems.AddRange(RegistryChecker.Check(tree));
        return problems;
    }

    [Fact]
    public void TheBrokenEntry_IsReadAsYamlMeansIt_AbiInsideTheNotes()
    {
        // A conforming parser keeps the indented "abi: 1" inside the block scalar: the entry has no abi at all.
        var json = RegistryYaml.Parse("notes: |\n  - first item\n  - The Friends tab shows the player and their friends.abi: 1\nhosts: [\"steamworks\"]\n");
        Assert.Equal("- first item\n- The Friends tab shows the player and their friends.abi: 1\n", json["notes"]!.GetValue<string>());
        Assert.False(json.ContainsKey("abi"));
    }

    [Fact]
    public void TrickyNotes_AreNormalized_AndReadBackFromTheBlockScalarAsWritten()
    {
        Assert.Equal(NormalizedNotes, ReleaseNotes.Normalize(TrickyNotes));

        var yaml = ReleaseNotes.BlockScalar("notes", ReleaseNotes.Normalize(TrickyNotes)) + "abi: 1\n";
        var json = RegistryYaml.Parse(yaml);
        Assert.Equal(NormalizedNotes + "\n", json["notes"]!.GetValue<string>());
        Assert.Equal(1, json["abi"]!.GetValue<long>());
        Assert.Equal(["notes", "abi"], json.Select(p => p.Key));
    }

    [Fact]
    public async Task NotesFromAFile_RoundTripThroughCheck_AndAbiJoinedOntoTheirLastLineIsAProblem()
    {
        var notesFile = Path.Combine(_work, "notes.md");
        await File.WriteAllTextAsync(notesFile, TrickyNotes, TestContext.Current.CancellationToken);

        Assert.Equal(0, await Version("https://example.com/stoker", "--notes", notesFile, "--released", "2026-11-06"));
        var written = await File.ReadAllTextAsync(Entry, TestContext.Current.CancellationToken);

        // released and notes after the signature, before the hook fields.
        var order = new[] { "\nsignature: ", "\nreleased: \"2026-11-06\"\n", "\nnotes: |2\n", "\nabi: 1\n", "\nmanifestSha256: ", "\nfiles:\n" }
            .Select(field => written.IndexOf(field, StringComparison.Ordinal)).ToList();
        Assert.DoesNotContain(-1, order);
        Assert.Equal(order.Order(), order);

        var entry = RegistryYaml.Parse(written);
        Assert.Equal(NormalizedNotes + "\n", entry["notes"]!.GetValue<string>());
        Assert.Equal(1, entry["abi"]!.GetValue<long>());
        Assert.Empty(Problems());
        Assert.Equal(0, await Cli.RunAsync(["check", _root]));

        // The hand edit that went wrong: the notes' last line lost its line end, and abi went into the notes.
        var broken = written.Replace("> last line, no line end\nabi: 1\n", "> last line, no line end abi: 1\n", StringComparison.Ordinal);
        Assert.NotEqual(written, broken);
        await File.WriteAllTextAsync(Entry, broken, TestContext.Current.CancellationToken);

        var problems = Problems();
        Assert.Contains(problems, p => p.StartsWith($"plugins/{Plugin}/1.0.0.yaml: ", StringComparison.Ordinal) && p.Contains("abi", StringComparison.Ordinal));
        Assert.Equal(1, await Cli.RunAsync(["check", _root]));
        Assert.Equal(1, await Cli.RunAsync(["compile", _root, "--out", Path.Combine(_work, "site")]));
    }

    [Fact]
    public async Task AHookVersionWithoutManifestSha256_IsAProblem()
    {
        Assert.Equal(0, await Version("https://example.com/stoker", "--no-notes"));
        var written = await File.ReadAllTextAsync(Entry, TestContext.Current.CancellationToken);
        Assert.DoesNotContain("notes:", written, StringComparison.Ordinal);
        Assert.DoesNotContain("released:", written, StringComparison.Ordinal);

        var without = string.Join('\n', written.Split('\n').Where(l => !l.StartsWith("manifestSha256: ", StringComparison.Ordinal)));
        await File.WriteAllTextAsync(Entry, without, TestContext.Current.CancellationToken);
        Assert.Contains(Problems(), p => p.Contains("manifestSha256", StringComparison.Ordinal));
    }

    [Fact]
    public async Task NotesAndReleased_ComeFromTheGitHubRelease()
    {
        var stub = new StubGitHub(HttpStatusCode.OK, """{ "tag_name": "v1.0.0", "published_at": "2026-11-05T23:39:02Z", "body": "## Changes\r\n\r\n- Fixed: a: b\r\n" }""");
        ReleaseNotes.Handler = stub;

        Assert.Equal(0, await Version("https://github.com/StokerHQ/example-plugin.git"));
        Assert.Equal("https://api.github.com/repos/StokerHQ/example-plugin/releases/tags/v1.0.0", stub.Requested?.ToString());

        var entry = RegistryYaml.Parse(await File.ReadAllTextAsync(Entry, TestContext.Current.CancellationToken));
        Assert.Equal("2026-11-05", entry["released"]!.GetValue<string>());
        Assert.Equal("## Changes\n\n- Fixed: a: b\n", entry["notes"]!.GetValue<string>());
        Assert.Empty(Problems());
    }

    [Fact]
    public async Task TheOptionsOverrideTheGitHubRelease()
    {
        var stub = new StubGitHub(HttpStatusCode.OK, """{ "published_at": "2026-11-05T10:00:00Z", "body": "From GitHub" }""");
        ReleaseNotes.Handler = stub;

        Assert.Equal(0, await Version("https://github.com/StokerHQ/example-plugin", "--no-notes", "--released", "2026-10"));
        var entry = RegistryYaml.Parse(await File.ReadAllTextAsync(Entry, TestContext.Current.CancellationToken));
        Assert.Equal("2026-10", entry["released"]!.GetValue<string>());
        Assert.False(entry.ContainsKey("notes"));
        Assert.Null(stub.Requested);
    }

    [Fact]
    public async Task WhenTheReleaseCannotBeRead_TheEntryIsWrittenWithoutNotesAndDate()
    {
        ReleaseNotes.Handler = new StubGitHub(HttpStatusCode.NotFound, """{ "message": "Not Found" }""");
        Assert.Equal(0, await Version("https://github.com/StokerHQ/example-plugin"));
        var entry = RegistryYaml.Parse(await File.ReadAllTextAsync(Entry, TestContext.Current.CancellationToken));
        Assert.False(entry.ContainsKey("notes"));
        Assert.False(entry.ContainsKey("released"));
        Assert.Empty(Problems());
    }

    [Fact]
    public async Task ADateThatIsNoDay_IsRefused()
    {
        Assert.Equal(1, await Version("https://example.com/stoker", "--released", "2026-02-30"));
        Assert.Equal(1, await Version("https://example.com/stoker", "--released", "6 November 2026"));
        Assert.False(File.Exists(Entry));
    }

    private sealed class StubGitHub(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public Uri? Requested { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requested = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }
}
