using System.Security.Cryptography;

namespace Stoker.Plugins.Registry;

/// <summary>
/// An ECDSA P-256 public key a plugin registry names: its own, which signs the compiled index's <c>timestamp.json</c>,
/// or a publisher's, which signs each version. Written as base64 of its DER SubjectPublicKeyInfo — the body of a
/// <c>-----BEGIN PUBLIC KEY-----</c> PEM on one line — the form Stoker's release keys take too.
/// </summary>
/// <param name="KeyId">The first 8 bytes of the SHA-256 of <paramref name="SubjectPublicKeyInfo"/>, lower-case hex.</param>
/// <param name="SubjectPublicKeyInfo">The key's DER SubjectPublicKeyInfo.</param>
public sealed record RegistryKey(string KeyId, byte[] SubjectPublicKeyInfo)
{
    /// <summary>The key as <c>registry.yaml</c> writes it: base64 of the DER SubjectPublicKeyInfo.</summary>
    public string Base64 => Convert.ToBase64String(SubjectPublicKeyInfo);

    /// <summary>
    /// A key from base64 or from a PEM <c>-----BEGIN PUBLIC KEY-----</c> block. Throws <see cref="FormatException"/> or
    /// <see cref="CryptographicException"/> when it is not an ECDSA P-256 public key.
    /// </summary>
    public static RegistryKey Parse(string text)
    {
        var body = text.Trim();
        if (body.StartsWith("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal))
            body = body.Replace("-----BEGIN PUBLIC KEY-----", "", StringComparison.Ordinal).Replace("-----END PUBLIC KEY-----", "", StringComparison.Ordinal);

        var spki = Convert.FromBase64String(string.Concat(body.Where(c => !char.IsWhiteSpace(c))));
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(spki, out var read);
        if (read != spki.Length || ecdsa.KeySize != 256) throw new CryptographicException("A registry key is ECDSA P-256.");
        return new RegistryKey(IdOf(spki), spki);
    }

    /// <summary>The public half of a private key, as a registry names it.</summary>
    public static RegistryKey Of(ECDsa key)
    {
        if (key.KeySize != 256) throw new CryptographicException("A registry key is ECDSA P-256.");
        var spki = key.ExportSubjectPublicKeyInfo();
        return new RegistryKey(IdOf(spki), spki);
    }

    /// <summary>A key's id: the first 8 bytes of the SHA-256 of its SubjectPublicKeyInfo, lower-case hex.</summary>
    public static string IdOf(ReadOnlySpan<byte> subjectPublicKeyInfo) => Convert.ToHexStringLower(SHA256.HashData(subjectPublicKeyInfo)[..8]);
}

/// <summary>
/// The signatures a plugin registry uses: ECDSA P-256 with SHA-256, in IEEE P1363 form (r and s, 32 bytes each), base64
/// — the scheme of Stoker's signed launcher releases. A publisher signs a version's <see cref="PluginVersionStatement"/>;
/// the registry signs its <c>timestamp.json</c>'s exact bytes.
/// </summary>
public static class RegistrySignature
{
    /// <summary>The <c>algorithm</c> a version's signature names.</summary>
    public const string Algorithm = "ecdsa-p256-sha256";

    /// <summary>Signs <paramref name="data"/>; the base64 a registry file carries.</summary>
    public static string Sign(ECDsa key, ReadOnlySpan<byte> data)
    {
        if (key.KeySize != 256) throw new CryptographicException("A registry key is ECDSA P-256.");
        return Convert.ToBase64String(key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    /// <summary>Whether <paramref name="signature"/> is <paramref name="key"/>'s over <paramref name="data"/>. False for anything malformed.</summary>
    public static bool Verify(RegistryKey key, ReadOnlySpan<byte> data, string? signature)
    {
        if (string.IsNullOrWhiteSpace(signature)) return false;

        byte[] bytes;
        try { bytes = Convert.FromBase64String(signature.Trim()); }
        catch (FormatException) { return false; }
        if (bytes.Length != 64) return false;

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(key.SubjectPublicKeyInfo, out _);
            return ecdsa.KeySize == 256 && ecdsa.VerifyData(data, bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// A private key from PEM: an encrypted PKCS#8 block (<c>-----BEGIN ENCRYPTED PRIVATE KEY-----</c>, as
    /// <c>stoker-registry keygen</c> and <c>scripts/New-ReleaseSigningKey.ps1</c> write it) with its passphrase, or an
    /// unencrypted PKCS#8 or EC block. Throws when it is not an ECDSA P-256 private key.
    /// </summary>
    public static ECDsa LoadPrivateKey(string pem, ReadOnlySpan<char> passphrase)
    {
        var key = ECDsa.Create();
        try
        {
            if (pem.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal)) key.ImportFromEncryptedPem(pem, passphrase);
            else key.ImportFromPem(pem);
            if (key.KeySize != 256) throw new CryptographicException("A registry key is ECDSA P-256.");
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    /// <summary>Whether a PEM private key needs a passphrase to be read.</summary>
    public static bool IsEncrypted(string pem) => pem.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal);
}
