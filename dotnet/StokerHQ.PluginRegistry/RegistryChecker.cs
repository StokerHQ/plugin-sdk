namespace StokerHQ.PluginRegistry;

/// <summary>
/// Checks a registry the way a Stoker host does before it offers anything from it (plugin-registry.md §5): every
/// version is signed by a publisher the registry lists, that publisher owns the key's namespace, the registry's policy
/// takes the version's kind and integration provider, and the release's tag is one of the two shapes. Whether the
/// release's assets are the files the version names is checked by downloading them, which is the caller's.
/// </summary>
public static class RegistryChecker
{
    /// <summary>Every problem with the tree, as one line each; empty when there is none.</summary>
    public static IReadOnlyList<string> Check(RegistryTree tree)
    {
        var problems = new List<string>();
        var registry = tree.Registry;

        var publishers = new Dictionary<string, RegistryPublisher>(StringComparer.Ordinal);
        foreach (var publisher in registry.Publishers)
        {
            if (!publishers.TryAdd(publisher.Id, publisher)) problems.Add($"registry.yaml: publisher {publisher.Id} is listed twice");
            foreach (var ns in publisher.Namespaces.Where(n => !n.EndsWith('.')))
                problems.Add($"registry.yaml: publisher {publisher.Id}'s namespace {ns} does not end in a dot");
        }

        var namespaces = registry.Publishers.SelectMany(p => p.Namespaces.Select(n => (Publisher: p.Id, Namespace: n))).ToList();
        foreach (var a in namespaces)
        {
            foreach (var b in namespaces.Where(b => b.Publisher != a.Publisher && b.Namespace != a.Namespace && b.Namespace.StartsWith(a.Namespace, StringComparison.Ordinal)))
                problems.Add($"registry.yaml: {b.Publisher}'s namespace {b.Namespace} lies inside {a.Publisher}'s {a.Namespace}");
        }
        foreach (var shared in namespaces.GroupBy(n => n.Namespace, StringComparer.Ordinal).Where(g => g.Select(n => n.Publisher).Distinct().Count() > 1))
            problems.Add($"registry.yaml: namespace {shared.Key} belongs to more than one publisher");

        foreach (var plugin in tree.Plugins)
        {
            var key = plugin.Plugin.Key;
            var where = $"plugins/{plugin.Folder}";
            if (plugin.Folder != key) problems.Add($"{where}/plugin.yaml: key {key} is not the folder's name");
            if (registry.Policy.RefusedKinds.Contains(plugin.Plugin.Kind)) problems.Add($"{where}/plugin.yaml: this registry refuses kind {plugin.Plugin.Kind}");

            foreach (var version in plugin.Versions)
                problems.AddRange(CheckVersion($"{where}/{version.Version}.yaml", key, plugin.Plugin.Kind, version, registry, publishers));

            foreach (var duplicate in plugin.Versions.GroupBy(v => v.Version, StringComparer.Ordinal).Where(g => g.Count() > 1))
                problems.Add($"{where}: version {duplicate.Key} is there more than once");
        }

        return problems;
    }

    /// <summary>What is wrong with one version; empty when nothing is.</summary>
    public static IEnumerable<string> CheckVersion(
        string where, string pluginKey, string pluginKind, PluginVersionDocument version, RegistryDocument registry,
        IReadOnlyDictionary<string, RegistryPublisher> publishers)
    {
        if (version.Key != pluginKey) yield return $"{where}: key {version.Key} is not the plugin's {pluginKey}";
        if (version.Kind != pluginKind) yield return $"{where}: kind {version.Kind} is not the plugin's {pluginKind}";
        if (!IsTag(version.Release.Tag, pluginKey, version.Version))
            yield return $"{where}: release tag {version.Release.Tag} is neither v{version.Version} nor {pluginKey}/{version.Version}";

        if (registry.Policy.RefusedKinds.Contains(version.Kind)) yield return $"{where}: this registry refuses kind {version.Kind}";
        if (version.IntegrationProvider is { } provider && registry.Policy.RefusedIntegrationProviders.Contains(provider))
            yield return $"{where}: this registry refuses integrations for {provider}";

        foreach (var file in version.Files.GroupBy(f => (f.Os, f.Architecture)).Where(g => g.Count() > 1))
            yield return $"{where}: more than one file for {file.Key.Os}-{file.Key.Architecture}";

        if (version.Signature.Algorithm != RegistrySignature.Algorithm)
        {
            yield return $"{where}: signature algorithm {version.Signature.Algorithm} is not {RegistrySignature.Algorithm}";
            yield break;
        }
        if (!publishers.TryGetValue(version.Signature.Publisher, out var publisher))
        {
            yield return $"{where}: signed by {version.Signature.Publisher}, whom registry.yaml does not list";
            yield break;
        }
        if (!publisher.Owns(pluginKey)) yield return $"{where}: {publisher.Id} owns none of the namespaces {pluginKey} is in";

        byte[]? statement = null;
        string? unbuildable = null;
        try { statement = version.Statement; }
        catch (ArgumentException ex) { unbuildable = ex.Message; }

        if (statement is null) yield return $"{where}: the signed statement cannot be made: {unbuildable}";
        else if (!RegistrySignature.Verify(publisher.PublicKey, statement, version.Signature.Value))
            yield return $"{where}: the signature is not {publisher.Id}'s (key {publisher.PublicKey.KeyId}) over this version";
    }

    /// <summary>Whether a release tag names this version: <c>v&lt;version&gt;</c> in a one-plugin repository, <c>&lt;key&gt;/&lt;version&gt;</c> in one of several.</summary>
    public static bool IsTag(string tag, string pluginKey, string version) =>
        tag == $"v{version}" || tag == $"{pluginKey}/{version}";
}
