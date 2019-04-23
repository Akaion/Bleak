using System;

namespace Bleak.Syscall.Shellcode
{
    internal static class SyscallX86
    {
        internal static byte[] GetShellcode(byte[] syscallIndexBytes)
        {
            var shellcode = new byte[]
            {
                0xB8, 0x00, 0x00, 0x00, 0x00,                   // mov eax, syscall index
                0x33, 0xC9,                                     // xor ecx, ecx
                0x8D, 0x54, 0x24, 0x04,                         // lea edx, [esp+0x04]
                0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00, 0x00, // call DWORD PTR fs:0xC0
                0x83, 0xC4, 0x04,                               // add esp, 0x04
                0xC3                                            // ret
            };

            // Copy the syscall index into the shellcode

            Buffer.BlockCopy(syscallIndexBytes, 0, shellcode, 1, sizeof(uint));

            return shellcode;
        }
    }
}
