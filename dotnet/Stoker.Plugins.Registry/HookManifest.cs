using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json.Nodes;

namespace Stoker.Plugins.Registry;

/// <summary>
/// What a hook plugin's file says about itself: the operating system and architecture it was built for, and the
/// manifest <c>STOKER_PLUGIN_MANIFEST</c> compiled into its <c>.stkmeta</c> section — read without loading the file.
/// </summary>
/// <param name="Os">The registry's name for the operating system: <c>windows</c> or <c>linux</c>.</param>
/// <param name="Architecture">The registry's name for the architecture: <c>x86</c>, <c>x64</c> or <c>arm64</c>.</param>
/// <param name="ManifestBytes">The section's bytes up to its first NUL: what <see cref="ManifestSha256"/> is taken over.</param>
/// <param name="Manifest">The manifest, parsed.</param>
public sealed record HookManifest(string Os, string Architecture, byte[] ManifestBytes, JsonObject Manifest)
{
    /// <summary>The manifest section's name: eight characters, the most a PE section name holds.</summary>
    public const string Section = ".stkmeta";

    public const int MaxFileBytes = 16 * 1024 * 1024;
    public const int MaxManifestBytes = 64 * 1024;

    /// <summary>SHA-256 of the manifest's bytes, lower-case hex: the same for every file of one version.</summary>
    public string ManifestSha256 => FileHashes.Sha256(ManifestBytes);

    public string Id => Text("id");
    public string Version => Text("version");
    public string Type => Text("type");

    /// <summary>The hook ABI the plugin was built for.</summary>
    public int Abi => Manifest["abi"] is JsonValue v && v.TryGetValue<int>(out var abi) ? abi : throw new InvalidDataException("The manifest has no \"abi\".");

    /// <summary>The bootstraps that may load it; empty when the manifest names none (every one).</summary>
    public IReadOnlyList<string> Hosts => Manifest["hosts"] is JsonArray hosts
        ? [.. hosts.Select(h => h?.GetValue<string>() ?? throw new InvalidDataException("A host is text."))]
        : [];

    /// <summary>The configuration contract, as the manifest declares it; null when the plugin takes none.</summary>
    public JsonObject? Config => Manifest["config"] as JsonObject;

    /// <summary>
    /// Where a hook version's entry and this file disagree: the plugin and version it names, the file's operating
    /// system and architecture, and the fields an entry takes from the manifest (<c>abi</c>, <c>hosts</c>,
    /// <c>manifestSha256</c>, <c>config</c>). Empty when they agree.
    /// </summary>
    public IReadOnlyList<string> Differences(PluginVersionDocument version, PluginVersionFile file)
    {
        var problems = new List<string>();
        if (Id != version.Key) problems.Add($"its manifest is {Id}, not {version.Key}");
        if (Version != version.Version) problems.Add($"its manifest is version {Version}, not {version.Version}");
        if (Os != file.Os || Architecture != file.Architecture) problems.Add($"it is a {Os} {Architecture} library, not {file.Os} {file.Architecture}");
        if (version.Json["manifestSha256"]?.GetValue<string>() is { } digest && !digest.Equals(ManifestSha256, StringComparison.OrdinalIgnoreCase))
            problems.Add("its manifest is not the one `manifestSha256` names");
        if (version.Json["abi"] is JsonValue abi && abi.TryGetValue<int>(out var declared) && declared != Abi) problems.Add($"it is built for ABI {Abi}, not {declared}");
        var hosts = version.Json["hosts"] is JsonArray list ? list.Select(h => h?.GetValue<string>() ?? "").Order(StringComparer.Ordinal).ToList() : [];
        if (!hosts.SequenceEqual(Hosts.Order(StringComparer.Ordinal))) problems.Add("its hosts are not the entry's `hosts`");
        if (!JsonNode.DeepEquals(version.Json["config"], Config)) problems.Add("its configuration contract is not the entry's `config`");
        return problems;
    }

    private string Text(string name) =>
        Manifest[name] is JsonValue v && v.TryGetValue<string>(out var text) && text.Length > 0 ? text : throw new InvalidDataException($"The manifest has no \"{name}\".");

    /// <summary>
    /// Reads a PE (Windows DLL) or ELF (Linux shared object) hook plugin. Every offset comes from the file, so every
    /// read is bounds-checked and anything malformed is an <see cref="InvalidDataException"/>.
    /// </summary>
    public static HookManifest Read(byte[] image)
    {
        if (image.Length == 0 || image.Length > MaxFileBytes) throw new InvalidDataException("A plugin file must fit in 16 MiB.");
        try
        {
            var (os, architecture, bytes) =
                image.Length >= 4 && image[0] == 0x7f && image[1] == (byte)'E' && image[2] == (byte)'L' && image[3] == (byte)'F' ? ReadElf(image)
                : image.Length >= 2 && image[0] == (byte)'M' && image[1] == (byte)'Z' ? ReadPe(image)
                : throw new InvalidDataException("A hook plugin is a native Windows DLL or Linux shared object.");
            if (bytes is null) throw new InvalidDataException($"The file has no {Section} section: declare the plugin with STOKER_PLUGIN_MANIFEST.");
            var manifest = JsonNode.Parse(bytes) as JsonObject ?? throw new InvalidDataException("The manifest is not a JSON object.");
            return new HookManifest(os, architecture, bytes, manifest);
        }
        catch (Exception ex) when (ex is BadImageFormatException or ArgumentException or OverflowException or IndexOutOfRangeException or System.Text.Json.JsonException)
        {
            throw new InvalidDataException("The plugin file is not a valid native library with a manifest.", ex);
        }
    }

    private static (string, string, byte[]?) ReadPe(byte[] image)
    {
        using var reader = new PEReader(new MemoryStream(image, writable: false));
        var headers = reader.PEHeaders;
        if ((headers.CoffHeader.Characteristics & Characteristics.Dll) == 0 || headers.CorHeader is not null)
            throw new InvalidDataException("A hook plugin is a native DLL, not an executable or a managed assembly.");
        var architecture = headers.CoffHeader.Machine switch
        {
            Machine.I386 => "x86",
            Machine.Amd64 => "x64",
            Machine.Arm64 => "arm64",
            _ => throw new InvalidDataException("Hook plugins are x86, x64 or arm64."),
        };

        byte[]? manifest = null;
        foreach (var section in headers.SectionHeaders)
        {
            if (section.Name != Section) continue;
            if (manifest is not null) throw new InvalidDataException($"The DLL has more than one {Section} section.");
            // The raw data is padded to the file alignment and the virtual size is the real size, so the smaller of
            // the two is what the compiler put there.
            var length = Math.Min(section.SizeOfRawData, section.VirtualSize == 0 ? section.SizeOfRawData : section.VirtualSize);
            if (section.PointerToRawData < 0 || length < 0 || (long)section.PointerToRawData + length > image.Length)
                throw new InvalidDataException("The manifest section lies outside the file.");
            manifest = UpToNul(image.AsSpan(section.PointerToRawData, length));
        }
        return ("windows", architecture, manifest);
    }

    private static (string, string, byte[]?) ReadElf(byte[] image)
    {
        var span = image.AsSpan();
        if (span.Length < 52) throw new InvalidDataException("Truncated ELF header.");
        var is64 = span[4] switch { 1 => false, 2 => true, _ => throw new InvalidDataException("Unknown ELF class.") };
        if (span[5] != 1) throw new InvalidDataException("Only little-endian ELF plugins are supported.");
        if (is64 && span.Length < 64) throw new InvalidDataException("Truncated ELF header.");

        ushort U16(long offset) => BinaryPrimitives.ReadUInt16LittleEndian(Slice(image, offset, 2));
        uint U32(long offset) => BinaryPrimitives.ReadUInt32LittleEndian(Slice(image, offset, 4));
        ulong Word(long offset) => is64 ? BinaryPrimitives.ReadUInt64LittleEndian(Slice(image, offset, 8)) : U32(offset);

        // ET_DYN: a shared object. An executable cannot be loaded as a plugin.
        if (U16(16) != 3) throw new InvalidDataException("A hook plugin is a shared object (.so), not an executable.");
        var architecture = U16(18) switch
        {
            3 => "x86",
            62 => "x64",
            183 => "arm64",
            _ => throw new InvalidDataException("Hook plugins are x86, x64 or arm64."),
        };

        var sectionOffset = checked((long)Word(is64 ? 40 : 32));
        var entrySize = U16(is64 ? 58 : 46);
        var count = U16(is64 ? 60 : 48);
        var namesIndex = U16(is64 ? 62 : 50);
        if (count == 0 || count > 4096 || entrySize < (is64 ? 64 : 40) || namesIndex >= count)
            throw new InvalidDataException("Invalid ELF section table.");

        (uint Name, uint Type, long Offset, long Size) Entry(int i)
        {
            var at = checked(sectionOffset + (long)i * entrySize);
            return is64
                ? (U32(at), U32(at + 4), checked((long)Word(at + 24)), checked((long)Word(at + 32)))
                : (U32(at), U32(at + 4), U32(at + 16), U32(at + 20));
        }
        // SHT_NOBITS (8) has no bytes in the file; everything else must lie inside it.
        ReadOnlySpan<byte> Content((uint Name, uint Type, long Offset, long Size) s) => s.Type == 8 ? [] : Slice(image, s.Offset, s.Size);
        var names = Content(Entry(namesIndex));

        byte[]? manifest = null;
        for (var i = 0; i < count; i++)
        {
            var section = Entry(i);
            if (CString(names, section.Name) != Section) continue;
            if (manifest is not null) throw new InvalidDataException($"The library has more than one {Section} section.");
            manifest = UpToNul(Content(section));
        }
        return ("linux", architecture, manifest);
    }

    private static ReadOnlySpan<byte> Slice(ReadOnlySpan<byte> image, long offset, long length)
    {
        if (offset < 0 || length < 0 || offset > image.Length || length > image.Length - offset)
            throw new InvalidDataException("A structure lies outside the file.");
        return image.Slice((int)offset, (int)length);
    }

    private static string CString(ReadOnlySpan<byte> table, uint offset)
    {
        if (offset >= table.Length) return "";
        var rest = table[(int)offset..];
        var end = rest.IndexOf((byte)0);
        return end < 0 ? "" : Encoding.ASCII.GetString(rest[..Math.Min(end, 256)]);
    }

    private static byte[] UpToNul(ReadOnlySpan<byte> data)
    {
        var end = data.IndexOf((byte)0);
        var content = end < 0 ? data : data[..end];
        if (content.Length > MaxManifestBytes) throw new InvalidDataException("The plugin manifest must fit in 64 KiB.");
        return content.ToArray();
    }
}
