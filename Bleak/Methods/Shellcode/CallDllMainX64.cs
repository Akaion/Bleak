using System;

namespace Bleak.Methods.Shellcode
{
    internal static class CallDllMainX64
    {
        internal static byte[] GetShellcode(IntPtr dllBaseAddress, IntPtr entryPointAddress)
        {
            var shellcode = new byte[]
            {
                0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rcx, 0x00 (DLL base address)
                0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,                   // movabs rdx, 0x01 (DLL process attach)
                0x4D, 0x31, 0xC0,                                           // xor r8, r8 
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, 0x00 (entry point address)
                0xFF, 0xD0,                                                 // call rax
                0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
                0x31, 0xC0,                                                 // xor eax, eax
                0xC3                                                        // ret
            };

            // Copy the pointers into the shellcode

            var dllBaseAddressBytes = BitConverter.GetBytes((ulong) dllBaseAddress);

            var entryPointAddressBytes = BitConverter.GetBytes((ulong) entryPointAddress);

            Buffer.BlockCopy(dllBaseAddressBytes, 0, shellcode, 6, 8);

            Buffer.BlockCopy(entryPointAddressBytes, 0, shellcode, 26, 8);

            return shellcode;
        }
    }
}
