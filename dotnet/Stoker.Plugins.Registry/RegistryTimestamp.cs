using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Stoker.Plugins.Registry;

/// <summary>A <c>timestamp.json</c> a host has checked and takes as current.</summary>
/// <param name="Pinned">Every other file of the index by its path under the index's root, with the SHA-256 and size it must have.</param>
public sealed record VerifiedTimestamp(string Registry, long Serial, DateTimeOffset Generated, DateTimeOffset Expires, IReadOnlyDictionary<string, (string Sha256, long Size)> Pinned);

/// <summary>
/// Signing and checking a compiled index's <c>timestamp.json</c> (plugins/v1, <c>timestamp.schema.json</c>): the
/// registry key's signature over the file's exact bytes, in <c>timestamp.json.sig</c> as base64 and nothing else.
/// </summary>
/// <remarks>
/// A host takes an index only when the timestamp is signed by the registry's key, its serial is not lower than the one
/// the host holds (an index rolled back), its <c>expires</c> has not passed (an index held back), and every file the
/// host reads matches its pin. A refused index leaves the host with what it had.
/// </remarks>
public static class RegistryTimestamp
{
    /// <summary>The detached signature's text for <paramref name="timestamp"/>.</summary>
    public static string Sign(System.Security.Cryptography.ECDsa key, byte[] timestamp) => RegistrySignature.Sign(key, timestamp);

    /// <summary>
    /// Checks a timestamp and its signature. Returns the timestamp, or null with the reason in
    /// <paramref name="refusal"/>.
    /// </summary>
    /// <param name="heldSerial">The serial of the index the host holds; 0 for none.</param>
    public static VerifiedTimestamp? Verify(byte[] timestamp, string? signature, RegistryKey key, long heldSerial, DateTimeOffset now, out string? refusal)
    {
        if (!RegistrySignature.Verify(key, timestamp, signature?.Trim()))
        {
            refusal = $"timestamp.json is not signed by the registry's key ({key.KeyId})";
            return null;
        }

        JsonObject json;
        long serial;
        DateTimeOffset generated, expires;
        var pinned = new Dictionary<string, (string, long)>(StringComparer.Ordinal);
        string registry;
        try
        {
            json = JsonNode.Parse(timestamp) as JsonObject ?? throw new FormatException("not an object");
            registry = RegistryDocument.Text(json, "registry");
            serial = RegistryCompiler.SerialOf(timestamp);
            generated = DateTimeOffset.Parse(RegistryDocument.Text(json, "generated"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
            expires = DateTimeOffset.Parse(RegistryDocument.Text(json, "expires"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
            pinned[CompiledIndex.IndexPath] = Pin(RegistryDocument.Object(json["index"], "`index`"));
            foreach (var entry in RegistryDocument.Array(json, "plugins"))
            {
                var plugin = RegistryDocument.Object(entry, "A pinned plugin");
                pinned[CompiledIndex.PluginPath(RegistryDocument.Text(plugin, "key"))] = Pin(plugin);
            }
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException or InvalidOperationException)
        {
            refusal = $"timestamp.json cannot be read: {ex.Message}";
            return null;
        }

        if (serial < heldSerial)
        {
            refusal = $"timestamp.json has serial {serial}, older than the {heldSerial} already held: an index rolled back";
            return null;
        }
        if (expires <= now)
        {
            refusal = $"timestamp.json expired at {RegistryCompiler.Time(expires)}: an index held back, or a registry that has not re-signed";
            return null;
        }

        refusal = null;
        return new VerifiedTimestamp(registry, serial, generated, expires, pinned);
    }

    /// <summary>Whether <paramref name="bytes"/> are the file the timestamp pins at <paramref name="path"/>.</summary>
    public static bool Matches(VerifiedTimestamp timestamp, string path, ReadOnlySpan<byte> bytes) =>
        timestamp.Pinned.TryGetValue(path, out var pin) && pin.Size == bytes.Length && pin.Sha256 == RegistryCompiler.Sha256(bytes);

    private static (string, long) Pin(JsonObject json) =>
        (RegistryDocument.Text(json, "sha256"), json["size"] is JsonValue v && v.TryGetValue<long>(out var size) ? size : throw new FormatException("A pin's size is a number."));

    /// <summary>The signature file's bytes for a signature value: the base64, nothing else.</summary>
    public static byte[] SignatureFile(string signature) => Encoding.ASCII.GetBytes(signature);
}
