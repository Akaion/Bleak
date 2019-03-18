using System;

namespace Bleak.Methods.Shellcode
{
    internal static class CallDllMainX86
    {
        internal static byte[] GetShellcode(IntPtr dllBaseAddress, IntPtr entryPointAddress)
        {
            var shellcode = new byte[]
            {
                0x68, 0x00, 0x00, 0x00, 0x00, // push 0x00 (DLL base address)
                0x68, 0x01, 0x00, 0x00, 0x00, // push 0x01 (DLL process attach)
                0x68, 0x00, 0x00, 0x00, 0x00, // push 0x00
                0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00 (entry point address)
                0xFF, 0xD0,                   // call eax
                0x33, 0xC0,                   // xor eax, eax
                0xC3                          // ret
            };

            // Copy the pointers into the shellcode

            var dllBaseAddressBytes = BitConverter.GetBytes((uint) dllBaseAddress);

            var entryPointAddressBytes = BitConverter.GetBytes((uint) entryPointAddress);

            Buffer.BlockCopy(dllBaseAddressBytes, 0, shellcode, 1, 4);

            Buffer.BlockCopy(entryPointAddressBytes, 0, shellcode, 16, 4);

            return shellcode;
        }
    }
}
