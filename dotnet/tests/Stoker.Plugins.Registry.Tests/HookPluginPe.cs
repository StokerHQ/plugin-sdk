using System.Buffers.Binary;
using System.Text;

namespace Stoker.Registry.Tests;

/// <summary>A small native PE with a <c>.stkmeta</c> manifest section, as a hook plugin is laid out; never executed.</summary>
public static class HookPluginPe
{
    /// <param name="manifest">When given, a <c>.stkmeta</c> section holding it, as STOKER_PLUGIN_MANIFEST emits.</param>
    public static byte[] Create(bool x64 = true, string entry = "stoker_hook_plugin_init", string? manifest = null, bool arm64 = false)
    {
        var manifestBytes = manifest is null ? null : Encoding.UTF8.GetBytes(manifest + '\0');
        var manifestRaw = manifestBytes is null ? 0 : (manifestBytes.Length + 0x1ff) & ~0x1ff;
        var bytes = new byte[2048 + manifestRaw];
        void U16(int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset), value);
        void U32(int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
        U16(0, 0x5a4d); U32(0x3c, 0x80); U32(0x80, 0x4550);
        U16(0x84, arm64 ? (ushort)0xaa64 : x64 ? (ushort)0x8664 : (ushort)0x14c); U16(0x86, manifestBytes is null ? (ushort)1 : (ushort)2);
        var optionalSize = x64 || arm64 ? 240 : 224;
        U16(0x94, (ushort)optionalSize); U16(0x96, 0x2002);
        const int opt = 0x98;
        U16(opt, x64 || arm64 ? (ushort)0x20b : (ushort)0x10b);
        U32(opt + 32, 0x1000); U32(opt + 36, 0x200); U32(opt + 56, manifestBytes is null ? 0x2000u : 0x3000u); U32(opt + 60, 0x200); U16(opt + 68, 3);
        var directories = opt + (x64 || arm64 ? 112 : 96);
        U32(directories - 4, 16); U32(directories, 0x1100); U32(directories + 4, 0x100);
        var section = opt + optionalSize;
        Encoding.ASCII.GetBytes(".text").CopyTo(bytes, section);
        U32(section + 8, 0x600); U32(section + 12, 0x1000); U32(section + 16, 0x600); U32(section + 20, 0x200); U32(section + 36, 0x60000020);
        if (manifestBytes is not null)
        {
            var meta = section + 40;
            Encoding.ASCII.GetBytes(".stkmeta").CopyTo(bytes, meta);
            U32(meta + 8, (uint)manifestBytes.Length); U32(meta + 12, 0x2000); U32(meta + 16, (uint)manifestRaw); U32(meta + 20, 0x800); U32(meta + 36, 0x40000040);
            manifestBytes.CopyTo(bytes, 0x800);
        }
        bytes[0x200] = 0xb8; bytes[0x205] = 0xc3;
        U32(0x310, 1); U32(0x314, 1); U32(0x318, 1); U32(0x31c, 0x1140); U32(0x320, 0x1144); U32(0x324, 0x1148);
        U32(0x340, 0x1000); U32(0x344, 0x1160); U16(0x348, 0);
        Encoding.ASCII.GetBytes(entry + '\0').CopyTo(bytes, 0x360);
        return bytes;
    }

    /// <summary>A manifest as an SDK example would write it, with the given id, version and options schema.</summary>
    public static string Manifest(string id = "org.example.redirect", string version = "1.0.0", string? config = null, string type = "hook", int abi = 1) =>
        $$"""
        {"manifestVersion":1,"id":"{{id}}","name":"Redirect","type":"{{type}}","version":"{{version}}","abi":{{abi}},
         "description":"Rewrites paths.","hosts":["steamworks","ubisoft"]{{(config is null ? "" : ",\"config\":" + config)}}}
        """;
}
