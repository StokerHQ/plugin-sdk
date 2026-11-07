using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;

namespace StokerHQ.PluginRegistry;

/// <summary>Which of a registry's documents a <see cref="RegistrySchemas"/> check is for.</summary>
public enum RegistrySchema
{
    /// <summary><c>registry.yaml</c>: <c>plugins/v1/registry.schema.json</c>.</summary>
    Registry,

    /// <summary><c>plugins/&lt;key&gt;/plugin.yaml</c>: <c>plugins/v1/plugin.schema.json</c>.</summary>
    Plugin,

    /// <summary><c>plugins/&lt;key&gt;/&lt;version&gt;.yaml</c>: <c>plugins/v1/version.schema.json</c>.</summary>
    Version,
}

/// <summary>
/// Checks a registry's documents against StokerHQ/schemas' <c>plugins/v1</c> JSON Schemas, carried in this assembly, as
/// the schemas repository's <c>validate.py</c> does: every required field, every closed object, every pattern, and the
/// <c>uri</c> and <c>date</c> formats. A document that does not pass is not one the typed readers
/// (<see cref="RegistryDocument.From"/> and the rest) may take: they read only the fields they need, so a field the
/// schema requires but they do not use — a hook version's <c>abi</c> — would otherwise go missing without a word.
/// </summary>
public static class RegistrySchemas
{
    private const string ResourcePrefix = "StokerHQ.PluginRegistry.Schemas/";

    private static readonly Lazy<IReadOnlyDictionary<RegistrySchema, (JsonSchema Schema, JsonNode Source)>> Schemas = new(Load);

    // What the evaluator says of a field a closed object (additionalProperties: false) does not have.
    private const string FalseSchema = "All values fail against the false schema";

    private static readonly EvaluationOptions Evaluation = new() { OutputFormat = OutputFormat.Hierarchical, RequireFormatValidation = true };

    /// <summary>Every way <paramref name="document"/> breaks its schema, as <c>&lt;location&gt;: &lt;message&gt;</c>; empty when it does not.</summary>
    public static IReadOnlyList<string> Problems(JsonNode? document, RegistrySchema schema)
    {
        var element = JsonSerializer.SerializeToElement(document);
        var (built, source) = Schemas.Value[schema];
        var results = built.Evaluate(element, Evaluation);
        if (results.IsValid) return [];

        var problems = new List<string>();
        Collect(results, source, problems);
        return problems.Count > 0 ? problems : ["(document): does not match its schema"];
    }

    // Only what made the document fail. A subschema that failed under a keyword that passed (one branch of a oneOf
    // that another satisfied, an `if` that chose `else`) is no problem. The evaluator names no keyword for a failed
    // `not`, oneOf or anyOf, so those are described here: a `not` by the subschema the document matched (for a
    // version's kind rules, the fields that must go), a oneOf or anyOf by its place in the schema rather than by every
    // way each alternative failed.
    private static bool Collect(EvaluationResults node, JsonNode source, List<string> problems)
    {
        if (node.IsValid) return false;
        var location = node.InstanceLocation.ToString();
        if (location is "" or "/") location = "(document)";
        var before = problems.Count;
        void Add(string line)
        {
            if (!problems.Contains(line, StringComparer.Ordinal)) problems.Add(line);
        }

        foreach (var (_, message) in node.Errors ?? new Dictionary<string, string>())
            Add($"{location}: {(message == FalseSchema ? "not allowed here" : message.Replace("\\u0022", "\"", StringComparison.Ordinal))}");

        string? alternatives = null;
        foreach (var child in node.Details ?? [])
        {
            var path = child.EvaluationPath.ToString();
            var segments = path.Split('/');
            if (segments[^1] == "if") continue;
            if (segments.Length >= 2 && segments[^2] is "oneOf" or "anyOf" && int.TryParse(segments[^1], out _))
            {
                alternatives ??= segments[^2] == "oneOf"
                    ? $"matches none, or more than one, of the alternatives at {string.Join('/', segments[..^1])}"
                    : $"matches none of the alternatives at {string.Join('/', segments[..^1])}";
                continue;
            }
            if (segments[^1] == "not" && child.IsValid)
            {
                var forbidden = Subschema(source, path);
                Add($"{location}: must not match {(forbidden is null ? $"the schema at {path}" : forbidden.ToJsonString())}");
                continue;
            }
            Collect(child, source, problems);
        }

        if (alternatives is not null && problems.Count == before)
            Add($"{location}: {alternatives}");
        return problems.Count > before;
    }

    // The subschema at an evaluation path, when the path does not go through a $ref (whose target is another document).
    private static JsonNode? Subschema(JsonNode schema, string evaluationPath)
    {
        var node = schema;
        foreach (var segment in evaluationPath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var name = segment.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal);
            if (name == "$ref") return null;
            node = node switch
            {
                JsonObject o => o[name],
                JsonArray a when int.TryParse(name, out var i) && i < a.Count => a[i],
                _ => null,
            };
            if (node is null) return null;
        }
        return node;
    }

    private static IReadOnlyDictionary<RegistrySchema, (JsonSchema, JsonNode)> Load()
    {
        // A registry of their own, so nothing else registered in the process can stand in for one of them; the common
        // schema first, as the others refer to it, and plugin and registry before version, which refers to both.
        var options = new BuildOptions { SchemaRegistry = new SchemaRegistry() };
        (JsonSchema, JsonNode) Build(string path)
        {
            // The resource's name holds the folder separator of the machine that built the assembly.
            var assembly = typeof(RegistrySchemas).Assembly;
            var name = assembly.GetManifestResourceNames().FirstOrDefault(n => n.Replace('\\', '/') == ResourcePrefix + path)
                ?? throw new InvalidOperationException($"The assembly carries no schema {path}.");
            using var stream = assembly.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream);
            var text = reader.ReadToEnd();
            var schema = JsonSchema.FromText(text, options);
            options.SchemaRegistry.Register(schema);
            return (schema, JsonNode.Parse(text)!);
        }

        Build("metadata/v1/common.schema.json");
        var plugin = Build("plugins/v1/plugin.schema.json");
        var registry = Build("plugins/v1/registry.schema.json");
        var version = Build("plugins/v1/version.schema.json");
        return new Dictionary<RegistrySchema, (JsonSchema, JsonNode)>
        {
            [RegistrySchema.Registry] = registry,
            [RegistrySchema.Plugin] = plugin,
            [RegistrySchema.Version] = version,
        };
    }
}
