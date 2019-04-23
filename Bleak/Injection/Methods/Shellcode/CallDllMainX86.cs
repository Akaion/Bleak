using System;

namespace Bleak.Injection.Methods.Shellcode
{
    internal static class CallDllMainX86
    {
        internal static byte[] GetShellcode(IntPtr dllBaseAddress, IntPtr entryPointAddress)
        {
            var shellcode = new byte[]
            {
                0x68, 0x00, 0x00, 0x00, 0x00, // push DLL base address
                0x6A, 0x01,                   // push DLL process attach
                0x6A, 0x00,                   // push 0x00
                0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, entry point address
                0xFF, 0xD0,                   // call eax
                0x33, 0xC0,                   // xor eax, eax
                0xC3                          // ret
            };

            // Copy the pointers into the shellcode

            Buffer.BlockCopy(BitConverter.GetBytes((uint) dllBaseAddress), 0, shellcode, 1, sizeof(uint));

            Buffer.BlockCopy(BitConverter.GetBytes((uint) entryPointAddress), 0, shellcode, 10, sizeof(uint));

            return shellcode;
        }
    }
}
