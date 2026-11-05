using System.Text;

namespace StokerHQ.PluginRegistry;

/// <summary>One file of a plugin version as its signed statement names it.</summary>
/// <param name="Os">The <c>os</c> of the version's file entry (<c>windows</c>, <c>linux</c>, …).</param>
/// <param name="Architecture">The entry's <c>architecture</c> (<c>x64</c>, <c>x86</c>, <c>arm64</c>, <c>il</c>).</param>
/// <param name="FileName">The entry's <c>fileName</c>.</param>
/// <param name="Size">The file's size in bytes.</param>
/// <param name="Sha256">The file's SHA-256, hex.</param>
/// <param name="Blake3">The file's BLAKE3, hex.</param>
public sealed record StatementFile(string Os, string Architecture, string FileName, long Size, string Sha256, string Blake3);

/// <summary>
/// What a publisher signs for one plugin version (plugins/v1, <c>version.schema.json</c>, <c>signature</c>): UTF-8 text,
/// every line ending in <c>\n</c> —
/// <c>stoker-plugin-v1\n&lt;key&gt;\n&lt;version&gt;\n&lt;kind&gt;\n</c>, then one line per file in ordinal order of
/// <c>&lt;os&gt;\t&lt;architecture&gt;\t&lt;fileName&gt;</c>:
/// <c>&lt;os&gt;\t&lt;architecture&gt;\t&lt;fileName&gt;\t&lt;size&gt;\t&lt;sha256&gt;\t&lt;blake3&gt;\n</c>, hashes in
/// lower case.
/// </summary>
/// <remarks>
/// What a version is, and nothing a registry or a reader might add later: the key, version and kind, and every file by
/// name and hash. The release's URLs are not in it, so a version can move to another host, or be fetched from a mirror,
/// and still verify. A field holding a tab or a line break is refused rather than escaped: no key, version, kind, OS,
/// architecture or file name has one.
/// </remarks>
public static class PluginVersionStatement
{
    /// <summary>The statement's first line, naming its format.</summary>
    public const string Format = "stoker-plugin-v1";

    /// <summary>The statement's bytes. Throws <see cref="ArgumentException"/> for a field that is empty or holds a tab or line break.</summary>
    public static byte[] Build(string key, string version, string kind, IEnumerable<StatementFile> files)
    {
        var text = new StringBuilder();
        text.Append(Format).Append('\n')
            .Append(Field(key)).Append('\n')
            .Append(Field(version)).Append('\n')
            .Append(Field(kind)).Append('\n');

        foreach (var file in files.OrderBy(f => $"{f.Os}\t{f.Architecture}\t{f.FileName}", StringComparer.Ordinal))
        {
            if (file.Size < 0) throw new ArgumentException("A file's size is not negative.");
            text.Append(Field(file.Os)).Append('\t')
                .Append(Field(file.Architecture)).Append('\t')
                .Append(Field(file.FileName)).Append('\t')
                .Append(file.Size.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append('\t')
                .Append(Field(file.Sha256).ToLowerInvariant()).Append('\t')
                .Append(Field(file.Blake3).ToLowerInvariant()).Append('\n');
        }

        return Encoding.UTF8.GetBytes(text.ToString());
    }

    private static string Field(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.AsSpan().IndexOfAny('\t', '\r', '\n') >= 0)
            throw new ArgumentException("Every field of a signed plugin version is non-empty and holds no tab or line break.");
        return value;
    }
}
