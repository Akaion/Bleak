using System;

namespace Bleak.Injection.Methods.Shellcode
{
    internal static class CallDllMainX64
    {
        internal static byte[] GetShellcode(IntPtr dllBaseAddress, IntPtr entryPointAddress)
        {
            var shellcode = new byte[]
            {
                0x48, 0x83, 0xEC, 0x20,                                     // sub rsp, 0x20
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rcx, DLL base address
                0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rdx, DLL process attach
                0x4D, 0x31, 0xC0,                                           // xor r8, r8
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, entry point address
                0xFF, 0xD0,                                                 // call rax
                0x31, 0xC0,                                                 // xor eax, eax
                0x48, 0x83, 0xC4, 0x20,                                     // add rsp, 0x20
                0xC3                                                        // ret
            };

            // Copy the pointers into the shellcode

            Buffer.BlockCopy(BitConverter.GetBytes((ulong) dllBaseAddress), 0, shellcode, 6, sizeof(ulong));

            Buffer.BlockCopy(BitConverter.GetBytes((ulong) entryPointAddress), 0, shellcode, 29, sizeof(ulong));

            return shellcode;
        }
    }
}
