using System.Text.RegularExpressions;

namespace StokerHQ.PluginRegistry;

/// <summary>
/// A plugin version as a registry orders them: semver (<c>major.minor.patch[-prerelease]</c>) with semver's
/// precedence, or a four-part .NET assembly version (<c>major.minor.build.revision</c>), which unpacker plugins carry
/// instead of a manifest and which differ only in the revision. Build metadata (<c>+…</c>) is not a version: two
/// files that differ only there would otherwise be the same version with different bytes.
/// </summary>
public readonly record struct PluginVersionNumber(long Major, long Minor, long Patch, string? Prerelease, long Revision = 0) : IComparable<PluginVersionNumber>
{
    private static readonly Regex Pattern = new(@"^(0|[1-9]\d{0,9})\.(0|[1-9]\d{0,9})\.(0|[1-9]\d{0,9})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$", RegexOptions.CultureInvariant);

    private static readonly Regex AssemblyPattern = new(@"^(\d{1,5})\.(\d{1,5})\.(\d{1,5})\.(\d{1,5})$", RegexOptions.CultureInvariant);

    public static bool TryParse(string? text, out PluginVersionNumber version)
    {
        version = default;
        if (text is null || text.Length > 64) return false;
        var match = Pattern.Match(text);
        if (!match.Success) return false;
        version = new PluginVersionNumber(long.Parse(match.Groups[1].Value), long.Parse(match.Groups[2].Value), long.Parse(match.Groups[3].Value),
            match.Groups[4].Success ? match.Groups[4].Value : null);
        return true;
    }

    /// <summary>A four-part .NET assembly version, kept as four numbers so 1.0.0.3 and 1.0.0.9 stay two versions.</summary>
    public static bool TryParseAssemblyVersion(string? text, out PluginVersionNumber version)
    {
        version = default;
        if (text is null) return false;
        var match = AssemblyPattern.Match(text);
        if (!match.Success) return false;
        version = new PluginVersionNumber(long.Parse(match.Groups[1].Value), long.Parse(match.Groups[2].Value), long.Parse(match.Groups[3].Value),
            null, long.Parse(match.Groups[4].Value));
        return true;
    }

    public static PluginVersionNumber ParseOrZero(string text) =>
        TryParse(text, out var v) || TryParseAssemblyVersion(text, out v) ? v : default;

    public int CompareTo(PluginVersionNumber other)
    {
        var c = Major.CompareTo(other.Major);
        if (c == 0) c = Minor.CompareTo(other.Minor);
        if (c == 0) c = Patch.CompareTo(other.Patch);
        if (c == 0) c = Revision.CompareTo(other.Revision);
        if (c != 0) return c;
        // A release outranks any prerelease of itself; prereleases compare field by field.
        if (Prerelease is null || other.Prerelease is null) return (Prerelease is null).CompareTo(other.Prerelease is null);
        var mine = Prerelease.Split('.');
        var theirs = other.Prerelease.Split('.');
        for (var i = 0; i < Math.Min(mine.Length, theirs.Length); i++)
        {
            var a = long.TryParse(mine[i], out var na);
            var b = long.TryParse(theirs[i], out var nb);
            c = a && b ? na.CompareTo(nb) : a ? -1 : b ? 1 : string.CompareOrdinal(mine[i], theirs[i]);
            if (c != 0) return c;
        }
        return mine.Length.CompareTo(theirs.Length);
    }

    public bool IsPrerelease => Prerelease is not null;

    public override string ToString() =>
        $"{Major}.{Minor}.{Patch}" + (Revision > 0 ? $".{Revision}" : "") + (Prerelease is null ? "" : "-" + Prerelease);
}
