using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using StokerHQ.PluginRegistry;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace StokerHQ.PluginRegistry.Tool;

/// <summary>
/// Reads a registry's YAML as JSON means it, the way the schemas repository's <c>validate.py</c> does: a plain scalar is
/// <c>null</c> (<c>null</c>, <c>~</c> or nothing), <c>true</c>, <c>false</c> or a JSON number, and anything else is text
/// — so <c>no</c> stays the word, <c>2013-01-14</c> a string and <c>010</c> not eight. A quoted scalar is always text.
/// A key that is not text, or appears twice in one mapping, is refused.
/// </summary>
public static partial class RegistryYaml
{
    [GeneratedRegex("^-?(?:0|[1-9][0-9]*)$")]
    private static partial Regex Integer();

    [GeneratedRegex(@"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?$")]
    private static partial Regex Number();

    /// <summary>The one document in <paramref name="yaml"/>, as a JSON object. Throws <see cref="FormatException"/> for anything else.</summary>
    public static JsonObject Parse(string yaml)
    {
        var stream = new YamlStream();
        try { stream.Load(new StringReader(yaml)); }
        catch (YamlException ex) { throw new FormatException($"not valid YAML: {ex.Message}", ex); }

        if (stream.Documents.Count != 1) throw new FormatException("a file holds exactly one document");
        return Convert(stream.Documents[0].RootNode) as JsonObject ?? throw new FormatException("the document is not a mapping");
    }

    private static JsonNode? Convert(YamlNode node)
    {
        switch (node)
        {
            case YamlMappingNode mapping:
                var json = new JsonObject();
                foreach (var (key, value) in mapping.Children)
                {
                    if (key is not YamlScalarNode { Value: { } name } scalar || Convert(scalar) is not JsonValue keyValue || keyValue.GetValueKind() != System.Text.Json.JsonValueKind.String)
                        throw new FormatException($"key at {key.Start} is not text - quote it");
                    if (json.ContainsKey(name)) throw new FormatException($"key '{name}' appears more than once in one mapping ({key.Start})");
                    json[name] = Convert(value);
                }
                return json;

            case YamlSequenceNode sequence:
                return new JsonArray(sequence.Children.Select(Convert).ToArray());

            case YamlScalarNode scalar:
                var text = scalar.Value ?? "";
                if (scalar.Style != ScalarStyle.Plain) return JsonValue.Create(text);
                if (text is "" or "~" or "null") return null;
                if (text == "true") return JsonValue.Create(true);
                if (text == "false") return JsonValue.Create(false);
                if (Integer().IsMatch(text) && long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var whole)) return JsonValue.Create(whole);
                if (Number().IsMatch(text)) return JsonValue.Create(double.Parse(text, CultureInfo.InvariantCulture));
                return JsonValue.Create(text);

            default:
                throw new FormatException($"unsupported YAML node at {node.Start}");
        }
    }

    /// <summary>
    /// Reads a registry root: <c>registry.yaml</c> and, under <c>plugins/</c>, every <c>&lt;key&gt;/plugin.yaml</c> and
    /// <c>&lt;key&gt;/&lt;version&gt;.yaml</c>. A file that cannot be read goes to <paramref name="problems"/> and is left
    /// out; what can be read is returned.
    /// </summary>
    public static RegistryTree? ReadTree(string root, List<string> problems)
    {
        var registryFile = Path.Combine(root, "registry.yaml");
        if (!File.Exists(registryFile))
        {
            problems.Add($"{root}: no registry.yaml - not a registry root");
            return null;
        }

        RegistryDocument registry;
        try { registry = RegistryDocument.From(Parse(File.ReadAllText(registryFile, Encoding.UTF8))); }
        catch (FormatException ex)
        {
            problems.Add($"registry.yaml: {ex.Message}");
            return null;
        }

        var plugins = new List<RegistryPlugin>();
        var folder = Path.Combine(root, "plugins");
        if (Directory.Exists(folder))
        {
            foreach (var directory in Directory.EnumerateDirectories(folder).OrderBy(d => d, StringComparer.Ordinal))
            {
                var name = Path.GetFileName(directory);
                PluginDocument plugin;
                try { plugin = PluginDocument.From(Parse(File.ReadAllText(Path.Combine(directory, "plugin.yaml"), Encoding.UTF8))); }
                catch (Exception ex) when (ex is FormatException or IOException)
                {
                    problems.Add($"plugins/{name}/plugin.yaml: {ex.Message}");
                    continue;
                }

                var versions = new List<PluginVersionDocument>();
                foreach (var file in Directory.EnumerateFiles(directory, "*.yaml").Where(f => Path.GetFileName(f) != "plugin.yaml").OrderBy(f => f, StringComparer.Ordinal))
                {
                    var relative = $"plugins/{name}/{Path.GetFileName(file)}";
                    try
                    {
                        var version = PluginVersionDocument.From(Parse(File.ReadAllText(file, Encoding.UTF8)));
                        if (Path.GetFileNameWithoutExtension(file) != version.Version) problems.Add($"{relative}: version {version.Version} is not the file's name");
                        versions.Add(version);
                    }
                    catch (Exception ex) when (ex is FormatException or IOException)
                    {
                        problems.Add($"{relative}: {ex.Message}");
                    }
                }

                plugins.Add(new RegistryPlugin(name, plugin, versions));
            }
        }

        return new RegistryTree(registry, plugins);
    }
}
