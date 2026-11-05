using System.Security.Cryptography;

namespace Stoker.Plugins.Registry;

/// <summary>The two hashes a registry names every file by, lower-case hex.</summary>
public static class FileHashes
{
    public static string Sha256(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    /// <summary>BLAKE3-256, the hash a Stoker chunk store already holds for every file it stores.</summary>
    public static string Blake3(ReadOnlySpan<byte> bytes) => global::Blake3.Hasher.Hash(bytes).ToString().ToLowerInvariant();
}
