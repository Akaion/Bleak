using System;

namespace Bleak.Syscall.Shellcode
{
    internal static class SyscallX64
    {
        internal static byte[] GetShellcode(uint syscallIndex)
        {
            var shellcode = new byte[]
                {
                0x4C, 0x8B, 0xD1,             // mov r10, rcx
                0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, syscall index
                0x0F, 0x05,                   // syscall
                0xC3                          // ret
                };

            // Copy the syscall index into the shellcode

            var syscallIndexBytes = BitConverter.GetBytes(syscallIndex);

            Buffer.BlockCopy(syscallIndexBytes, 0, shellcode, 4, sizeof(uint));

            return shellcode;
        }
    }
}
