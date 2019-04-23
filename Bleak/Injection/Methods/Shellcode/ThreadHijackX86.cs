using System;

namespace Bleak.Injection.Methods.Shellcode
{
    internal static class ThreadHijackX86
    {
        internal static byte[] GetShellcode(IntPtr instructionPointer, IntPtr dllPathAddress, IntPtr loadLibraryAddress)
        {
            var shellcode = new byte[]
            {
                0x68, 0x00, 0x00, 0x00, 0x00, // push instruction pointer
                0x9C,                         // pushf
                0x60,                         // pusha
                0x68, 0x00, 0x00, 0x00, 0x00, // push DLL path address
                0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, LoadLibrary address
                0xFF, 0xD0,                   // call eax
                0x61,                         // popa
                0x9D,                         // popf
                0xC3                          // ret
            };

            // Copy the pointers into the shellcode

            Buffer.BlockCopy(BitConverter.GetBytes((uint) instructionPointer), 0, shellcode, 1, sizeof(uint));

            Buffer.BlockCopy(BitConverter.GetBytes((uint) dllPathAddress), 0, shellcode, 8, sizeof(uint));

            Buffer.BlockCopy(BitConverter.GetBytes((uint) loadLibraryAddress), 0, shellcode, 13, sizeof(uint));

            return shellcode;
        }
    }
}
