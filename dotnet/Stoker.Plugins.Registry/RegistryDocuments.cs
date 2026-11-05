using System.Text.Json.Nodes;

namespace Stoker.Plugins.Registry;

/// <summary>
/// A plugin registry's tree, read (plugins/v1): <c>registry.yaml</c>, and per plugin its <c>plugin.yaml</c> and every
/// <c>&lt;version&gt;.yaml</c>. Each document is kept whole as JSON (<see cref="RegistryDocument.Json"/> and the rest),
/// so the compiled index carries every field the files have, those this code does not know included; the typed
/// properties are what checking and compiling need.
/// </summary>
/// <remarks>
/// Reading YAML is the caller's: <c>stoker-registry</c> parses the files and hands the documents over as JSON, so Core
/// takes no YAML dependency. The same documents arrive as JSON from a compiled index.
/// </remarks>
public sealed record RegistryTree(RegistryDocument Registry, IReadOnlyList<RegistryPlugin> Plugins);

/// <summary>One plugin of a registry: its <c>plugin.yaml</c> and its versions, in no particular order.</summary>
/// <param name="Folder">The folder's name under <c>plugins/</c>, which has to be the key.</param>
public sealed record RegistryPlugin(string Folder, PluginDocument Plugin, IReadOnlyList<PluginVersionDocument> Versions);

/// <summary><c>registry.yaml</c>: who the registry is, its key, its publishers and what it refuses.</summary>
public sealed record RegistryDocument(
    string Name, string Url, RegistryKey Key, IReadOnlyList<RegistryPublisher> Publishers, RegistryPolicy Policy,
    IReadOnlyList<string> Mirrors, JsonObject Json)
{
    /// <summary>Reads the typed parts of a <c>registry.yaml</c>. Throws <see cref="FormatException"/> for one it cannot read.</summary>
    public static RegistryDocument From(JsonObject json)
    {
        var publishers = Array(json, "publishers").Select(p => RegistryPublisher.From(Object(p, "publishers[]"))).ToList();
        var policy = json["policy"] is JsonObject p2 ? RegistryPolicy.From(p2) : RegistryPolicy.None;
        return new RegistryDocument(Text(json, "name"), Text(json, "url"), KeyOf(json, "key"), publishers, policy,
            OptionalArray(json, "mirrors").Select(m => m?.GetValue<string>() ?? throw new FormatException("A mirror is a URL.")).ToList(), json);
    }

    internal static string Text(JsonObject json, string name) =>
        json[name] is JsonValue v && v.TryGetValue<string>(out var s) && s.Length > 0 ? s : throw new FormatException($"`{name}` is missing or not text.");

    internal static string? OptionalText(JsonObject json, string name) =>
        json[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    internal static JsonArray Array(JsonObject json, string name) =>
        json[name] as JsonArray ?? throw new FormatException($"`{name}` is missing or not a list.");

    internal static IEnumerable<JsonNode?> OptionalArray(JsonObject json, string name) =>
        json[name] as JsonArray ?? [];

    internal static JsonObject Object(JsonNode? node, string what) =>
        node as JsonObject ?? throw new FormatException($"{what} is not a mapping.");

    internal static RegistryKey KeyOf(JsonObject json, string name)
    {
        try { return RegistryKey.Parse(Text(json, name)); }
        catch (Exception ex) when (ex is not FormatException) { throw new FormatException($"`{name}` is not an ECDSA P-256 public key.", ex); }
    }
}

/// <summary>A publisher a registry accepts: the key its versions are signed with, and the key prefixes it owns.</summary>
public sealed record RegistryPublisher(string Id, string Name, RegistryKey PublicKey, IReadOnlyList<string> Namespaces)
{
    /// <summary>Whether this publisher may publish <paramref name="pluginKey"/>: one of its namespaces is a prefix of it.</summary>
    public bool Owns(string pluginKey) => Namespaces.Any(n => pluginKey.StartsWith(n, StringComparison.Ordinal) && pluginKey.Length > n.Length);

    internal static RegistryPublisher From(JsonObject json) =>
        new(RegistryDocument.Text(json, "id"), RegistryDocument.Text(json, "name"), RegistryDocument.KeyOf(json, "publicKey"),
            RegistryDocument.Array(json, "namespaces").Select(n => n?.GetValue<string>() ?? throw new FormatException("A namespace is text.")).ToList());
}

/// <summary>What a registry refuses, whoever signed it.</summary>
public sealed record RegistryPolicy(IReadOnlySet<string> RefusedKinds, IReadOnlySet<string> RefusedIntegrationProviders)
{
    /// <summary>A registry that refuses nothing.</summary>
    public static RegistryPolicy None { get; } = new(new HashSet<string>(), new HashSet<string>());

    internal static RegistryPolicy From(JsonObject json) =>
        new(Set(json, "refusedKinds"), Set(json, "refusedIntegrationProviders"));

    private static HashSet<string> Set(JsonObject json, string name) =>
        RegistryDocument.OptionalArray(json, name).Select(n => n?.GetValue<string>() ?? "").ToHashSet(StringComparer.Ordinal);
}

/// <summary>A plugin's <c>plugin.yaml</c>.</summary>
public sealed record PluginDocument(string Key, string Kind, JsonObject Json)
{
    /// <summary>Reads the typed parts of a <c>plugin.yaml</c>. Throws <see cref="FormatException"/> for one it cannot read.</summary>
    public static PluginDocument From(JsonObject json) => new(RegistryDocument.Text(json, "key"), RegistryDocument.Text(json, "kind"), json);
}

/// <summary>Where a version's files were released: a repository and the release's tag.</summary>
public sealed record PluginRelease(string Repository, string Tag);

/// <summary>A version's signature: the publisher who signed it, the algorithm, and the base64 value.</summary>
public sealed record PluginVersionSignature(string Publisher, string Algorithm, string Value);

/// <summary>One file of a version: <see cref="StatementFile"/> plus where the release serves it.</summary>
public sealed record PluginVersionFile(string Os, string Architecture, string FileName, long Size, string Sha256, string Blake3, string Url)
{
    /// <summary>The file as the signed statement names it.</summary>
    public StatementFile Statement => new(Os, Architecture, FileName, Size, Sha256, Blake3);
}

/// <summary>One <c>&lt;version&gt;.yaml</c>.</summary>
/// <param name="IntegrationProvider">For an <c>integration</c>, the store SDK it replaces; null otherwise.</param>
public sealed record PluginVersionDocument(
    string Key, string Version, string Kind, PluginRelease Release, PluginVersionSignature Signature,
    IReadOnlyList<PluginVersionFile> Files, string? IntegrationProvider, JsonObject Json)
{
    /// <summary>The statement the publisher signed for this version.</summary>
    public byte[] Statement => PluginVersionStatement.Build(Key, Version, Kind, Files.Select(f => f.Statement));

    /// <summary>Reads the typed parts of a <c>&lt;version&gt;.yaml</c>. Throws <see cref="FormatException"/> for one it cannot read.</summary>
    public static PluginVersionDocument From(JsonObject json)
    {
        var release = RegistryDocument.Object(json["release"], "`release`");
        var signature = RegistryDocument.Object(json["signature"], "`signature`");
        var files = RegistryDocument.Array(json, "files").Select(f =>
        {
            var file = RegistryDocument.Object(f, "A file");
            var size = file["size"] is JsonValue s && s.TryGetValue<long>(out var n) ? n : throw new FormatException("A file's `size` is a number.");
            return new PluginVersionFile(RegistryDocument.Text(file, "os"), RegistryDocument.Text(file, "architecture"), RegistryDocument.Text(file, "fileName"),
                size, RegistryDocument.Text(file, "sha256"), RegistryDocument.Text(file, "blake3"), RegistryDocument.Text(file, "url"));
        }).ToList();

        return new PluginVersionDocument(
            RegistryDocument.Text(json, "key"), RegistryDocument.Text(json, "version"), RegistryDocument.Text(json, "kind"),
            new PluginRelease(RegistryDocument.Text(release, "repository"), RegistryDocument.Text(release, "tag")),
            new PluginVersionSignature(RegistryDocument.Text(signature, "publisher"), RegistryDocument.Text(signature, "algorithm"), RegistryDocument.Text(signature, "value")),
            files,
            json["integration"] is JsonObject integration ? RegistryDocument.OptionalText(integration, "provider") : null,
            json);
    }
}
