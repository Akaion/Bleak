using System;

namespace Bleak.Methods.Shellcode
{
    internal static class ThreadHijackX86
    {
        internal static byte[] GetShellcode(IntPtr instructionPointer, IntPtr dllPathAddress, IntPtr loadLibraryAddress)
        {
            var shellcode = new byte[]
            {
                0x68, 0x00, 0x00, 0x00, 0x00, // push 0x00 (Instruction pointer)
                0x9C,                         // pushf
                0x60,                         // pusha
                0x68, 0x00, 0x00, 0x00, 0x00, // push 0x00 (DLL path address)
                0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00 (LoadLibrary address)
                0xFF, 0xD0,                   // call eax
                0x61,                         // popa
                0x9D,                         // popf
                0xC3                          // ret
            };

            // Copy the values into the shellcode

            var instructionPointerBytes = BitConverter.GetBytes((uint) instructionPointer);

            var dllPathAddressBytes = BitConverter.GetBytes((uint) dllPathAddress);

            var loadLibraryAddressBytes = BitConverter.GetBytes((uint) loadLibraryAddress);

            Buffer.BlockCopy(instructionPointerBytes, 0, shellcode, 1, 4);

            Buffer.BlockCopy(dllPathAddressBytes, 0, shellcode, 8, 4);

            Buffer.BlockCopy(loadLibraryAddressBytes, 0, shellcode, 13, 4);

            return shellcode;
        }
    }
}
