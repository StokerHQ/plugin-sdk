using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace StokerHQ.PluginRegistry.Tool;

/// <summary>
/// A version entry's changelog: <c>notes</c> (Markdown) and <c>released</c> (a partial date), which the publisher's
/// signature does not cover. <c>stoker-registry version</c> takes them from the GitHub release the entry names, or from
/// its options, and writes the notes as a YAML literal block scalar.
/// </summary>
public static partial class ReleaseNotes
{
    /// <summary>What <c>version</c> needs of a GitHub release: its body, and its publication date as <c>YYYY-MM-DD</c> (null for a draft).</summary>
    public sealed record GitHubRelease(string? Body, string? Published);

    /// <summary>The environment variable whose token, when set, is sent to GitHub's API.</summary>
    public const string TokenVariable = "GITHUB_TOKEN";

    /// <summary>What GitHub's API is reached through; tests put a stand-in here.</summary>
    internal static HttpMessageHandler? Handler { get; set; }

    // common.schema.json#/$defs/partialDate.
    [GeneratedRegex(@"^\d{4}(?:-(?:0[1-9]|1[0-2])(?:-(?:0[1-9]|[12]\d|3[01]))?)?$")]
    private static partial Regex PartialDate();

    /// <summary>Whether <paramref name="text"/> is a partial date (<c>2026</c>, <c>2026-11</c>, <c>2026-11-06</c>) and, when it names a day, a day the calendar has.</summary>
    public static bool IsPartialDate(string text) =>
        PartialDate().IsMatch(text) && (text.Length != 10 || DateOnly.TryParseExact(text, "yyyy-MM-dd", out _));

    /// <summary>
    /// The release <paramref name="tag"/> of <paramref name="repository"/> (<c>https://github.com/&lt;owner&gt;/&lt;name&gt;</c>),
    /// read through GitHub's REST API. Null, with the reason written to <paramref name="log"/>, when the repository is not
    /// on github.com or the API does not answer with the release.
    /// </summary>
    public static async Task<GitHubRelease?> FetchAsync(string repository, string tag, TextWriter log)
    {
        const string without = "the entry is written without notes and released date";
        if (!Uri.TryCreate(repository, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps
            || !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
            || uri.AbsolutePath.Trim('/').Split('/') is not [var owner, var name] || owner.Length == 0 || name.Length == 0)
        {
            log.WriteLine($"stoker-registry: {repository} is not a repository on github.com; {without}.");
            return null;
        }
        if (name.EndsWith(".git", StringComparison.OrdinalIgnoreCase)) name = name[..^4];

        var tagPath = string.Join('/', tag.Split('/').Select(Uri.EscapeDataString));
        var url = $"https://api.github.com/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(name)}/releases/tags/{tagPath}";
        using var http = Handler is null ? new HttpClient() : new HttpClient(Handler, disposeHandler: false);
        http.Timeout = TimeSpan.FromSeconds(30);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd("stoker-registry");
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
        if (Environment.GetEnvironmentVariable(TokenVariable) is { Length: > 0 } token) request.Headers.Authorization = new("Bearer", token);

        try
        {
            using var response = await http.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                log.WriteLine($"stoker-registry: GitHub answered {(int)response.StatusCode} {response.ReasonPhrase} for the release {tag} of {owner}/{name}; {without}.");
                return null;
            }

            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var root = json.RootElement;
            var body = root.TryGetProperty("body", out var b) && b.ValueKind == JsonValueKind.String ? b.GetString() : null;
            var published = root.TryGetProperty("published_at", out var p) && p.ValueKind == JsonValueKind.String
                && p.GetString() is { Length: >= 10 } at && IsPartialDate(at[..10]) ? at[..10] : null;
            return new GitHubRelease(body, published);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or InvalidOperationException)
        {
            log.WriteLine($"stoker-registry: the release {tag} of {owner}/{name} could not be read from GitHub ({ex.Message}); {without}.");
            return null;
        }
    }

    /// <summary>
    /// Notes as they are stored: line feeds only (CRLF, CR and the YAML 1.1 line breaks NEL, LS and PS become LF), no
    /// byte order mark, no character YAML cannot hold, no blank lines or spaces at either end. Empty when nothing is left.
    /// </summary>
    public static string Normalize(string text)
    {
        var builder = new StringBuilder(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '\r')
            {
                builder.Append('\n');
                if (i + 1 < text.Length && text[i + 1] == '\n') i++;
            }
            else if (c is '\u0085' or '\u2028' or '\u2029') builder.Append('\n');
            else if (char.IsSurrogatePair(text, i))
            {
                builder.Append(c).Append(text[++i]);
            }
            else if (IsPrintable(c)) builder.Append(c);
        }

        // Trailing blank lines and spaces go; so do leading blank lines, but not the first line's own indentation.
        var result = builder.ToString().TrimEnd();
        var start = 0;
        for (var i = 0; i < result.Length && result[i] is ' ' or '\t' or '\n'; i++)
            if (result[i] == '\n') start = i + 1;
        return result[start..];
    }

    // YAML's c-printable, without the line breaks, which Normalize handles; a lone surrogate is not printable.
    private static bool IsPrintable(char c) =>
        c is '\t' or '\n' or (>= ' ' and <= '~') or (>= '\u00A0' and <= '\uD7FF') or (>= '\uE000' and <= '\uFFFD') && c != '\uFEFF';

    /// <summary>
    /// <c>&lt;key&gt;: |2</c> and <paramref name="text"/> (normalised) as a literal block scalar indented by two spaces,
    /// which reads back as <paramref name="text"/> plus one line feed. The indentation indicator is explicit, so a first
    /// line that starts with spaces cannot set a deeper indentation for the lines after it; every line, whatever it
    /// holds (<c>: </c>, <c>#</c>, quotes, <c>---</c>, something like a key), is content of the scalar, and the
    /// scalar ends in a line feed, so the next key starts on a line of its own.
    /// </summary>
    public static string BlockScalar(string key, string text)
    {
        var builder = new StringBuilder().Append(key).Append(": |2\n");
        foreach (var line in text.Split('\n'))
        {
            if (line.Length > 0) builder.Append("  ").Append(line);
            builder.Append('\n');
        }
        return builder.ToString();
    }
}
