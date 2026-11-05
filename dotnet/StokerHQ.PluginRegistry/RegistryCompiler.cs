using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using ZstdSharp;

namespace StokerHQ.PluginRegistry;

/// <summary>A compiled index's files, by their path under the index's root (<c>index/v1/…</c>).</summary>
/// <param name="Serial">The serial every file of this index carries.</param>
public sealed record CompiledIndex(long Serial, IReadOnlyDictionary<string, byte[]> Files)
{
    /// <summary>Where the index's one signed file is.</summary>
    public const string TimestampPath = "index/v1/timestamp.json";

    /// <summary>Where the timestamp's detached signature is.</summary>
    public const string SignaturePath = "index/v1/timestamp.json.sig";

    /// <summary>Where the whole index is, compressed.</summary>
    public const string IndexPath = "index/v1/plugins.json.zst";

    /// <summary>Where one plugin's document is.</summary>
    public static string PluginPath(string key) => $"index/v1/plugins/{key}.json";
}

/// <summary>
/// Compiles a registry's tree into what hosts read (plugins/v1, <c>index.schema.json</c>, <c>timestamp.schema.json</c>):
/// <c>index/v1/plugins.json.zst</c> — the registry's key, publishers, policy and mirrors, and every plugin with every
/// version — one <c>index/v1/plugins/&lt;key&gt;.json</c> per plugin, and <c>index/v1/timestamp.json</c>, which pins
/// every other file by SHA-256 and size and is the one file the registry signs.
/// </summary>
/// <remarks>
/// The same tree, serial and times give the same bytes: plugins in ordinal order of key, versions in ascending version
/// order, every document's fields in the order its file has them, JSON with <c>\n</c> line ends whatever the system,
/// zstd at a fixed level. A registry can then recompile and see whether anything changed by comparing files.
/// </remarks>
public static class RegistryCompiler
{
    /// <summary>The zstd level the index is compressed at.</summary>
    public const int CompressionLevel = 19;

    private static readonly JsonSerializerOptions Indented = new()
    {
        WriteIndented = true,
        NewLine = "\n",
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly JsonSerializerOptions Compact = new()
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// The compiled index for <paramref name="tree"/>, at <paramref name="serial"/>, made at <paramref name="generated"/>
    /// and current until <paramref name="expires"/>.
    /// </summary>
    public static CompiledIndex Compile(RegistryTree tree, long serial, DateTimeOffset generated, DateTimeOffset expires)
    {
        if (serial < 1) throw new ArgumentOutOfRangeException(nameof(serial), "A serial is 1 or more.");
        if (expires <= generated) throw new ArgumentException("An index expires after it is made.", nameof(expires));

        var registry = tree.Registry;
        var files = new SortedDictionary<string, byte[]>(StringComparer.Ordinal);
        var entries = new JsonArray();
        var pinned = new JsonArray();

        foreach (var plugin in tree.Plugins.OrderBy(p => p.Plugin.Key, StringComparer.Ordinal))
        {
            var versions = new JsonArray(plugin.Versions
                .OrderBy(v => PluginVersionNumber.ParseOrZero(v.Version))
                .ThenBy(v => v.Version, StringComparer.Ordinal)
                .Select(v => (JsonNode)Document(v.Json)).ToArray());

            entries.Add(new JsonObject { ["plugin"] = Document(plugin.Plugin.Json), ["versions"] = versions.DeepClone() });

            var document = new JsonObject
            {
                ["schemaVersion"] = "1.0",
                ["registry"] = registry.Name,
                ["serial"] = serial,
                ["plugin"] = Document(plugin.Plugin.Json),
                ["versions"] = versions,
            };
            var bytes = Encoding.UTF8.GetBytes(document.ToJsonString(Indented) + "\n");
            files[CompiledIndex.PluginPath(plugin.Plugin.Key)] = bytes;
            pinned.Add(new JsonObject { ["key"] = plugin.Plugin.Key, ["sha256"] = Sha256(bytes), ["size"] = bytes.LongLength });
        }

        var index = new JsonObject
        {
            ["schemaVersion"] = "1.0",
            ["registry"] = registry.Name,
            ["serial"] = serial,
            ["generated"] = Time(generated),
            ["key"] = registry.Key.Base64,
            ["publishers"] = registry.Json["publishers"]?.DeepClone(),
        };
        if (registry.Json["policy"] is { } policy) index["policy"] = policy.DeepClone();
        if (registry.Json["mirrors"] is { } mirrors) index["mirrors"] = mirrors.DeepClone();
        index["plugins"] = entries;

        using var compressor = new Compressor(CompressionLevel);
        var compressed = compressor.Wrap(Encoding.UTF8.GetBytes(index.ToJsonString(Compact))).ToArray();
        files[CompiledIndex.IndexPath] = compressed;

        var timestamp = new JsonObject
        {
            ["schemaVersion"] = "1.0",
            ["registry"] = registry.Name,
            ["serial"] = serial,
            ["generated"] = Time(generated),
            ["expires"] = Time(expires),
            ["index"] = new JsonObject { ["sha256"] = Sha256(compressed), ["size"] = compressed.LongLength },
            ["plugins"] = pinned,
        };
        files[CompiledIndex.TimestampPath] = Encoding.UTF8.GetBytes(timestamp.ToJsonString(Indented) + "\n");

        return new CompiledIndex(serial, files);
    }

    /// <summary>The serial a <c>timestamp.json</c> carries. Throws <see cref="FormatException"/> for one without a serial.</summary>
    public static long SerialOf(byte[] timestamp) =>
        JsonNode.Parse(timestamp)?["serial"] is JsonValue v && v.TryGetValue<long>(out var serial) && serial >= 1
            ? serial
            : throw new FormatException("timestamp.json has no serial.");

    /// <summary>A document as the index carries it: everything its file has, but the editor's <c>$schema</c> hint.</summary>
    private static JsonObject Document(JsonObject source)
    {
        var copy = (JsonObject)source.DeepClone();
        copy.Remove("$schema");
        return copy;
    }

    internal static string Sha256(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    internal static string Time(DateTimeOffset time) =>
        time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
