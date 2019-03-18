using System;

namespace Bleak.Methods.Shellcode
{
    internal static class ThreadHijackX64
    {
        internal static byte[] GetShellcode(IntPtr instructionPointer, IntPtr dllPathAddress, IntPtr loadLibraryAddress)
        {
            var shellcode = new byte[]
            {
                0x50,                                                       // push rax
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x00 (old instruction pointer)
                0x9C,                                                       // pushf
                0x51,                                                       // push rcx
                0x52,                                                       // push rdx
                0x53,                                                       // push rbx
                0x55,                                                       // push rbp
                0x56,                                                       // push rsi
                0x57,                                                       // push rdi
                0x41, 0x50,                                                 // push r8
                0x41, 0x51,                                                 // push r9
                0x41, 0x52,                                                 // push r10
                0x41, 0x53,                                                 // push r11
                0x41, 0x54,                                                 // push r12
                0x41, 0x55,                                                 // push r13
                0x41, 0x56,                                                 // push r14
                0x41, 0x57,                                                 // push r15
                0x68, 0x00, 0x00, 0x00, 0x00,                               // push 0x00
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rcx, 0x00 (DLL path address)
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, 0x00 (load library address)
                0xFF, 0xD0,                                                 // call rax
                0x58,                                                       // pop rax
                0x41, 0x5F,                                                 // pop r15
                0x41, 0x5E,                                                 // pop r14
                0x41, 0x5D,                                                 // pop r13
                0x41, 0x5C,                                                 // pop r12
                0x41, 0x5B,                                                 // pop r11
                0x41, 0x5A,                                                 // pop r10
                0x41, 0x59,                                                 // pop r9
                0x41, 0x58,                                                 // pop r8
                0x5F,                                                       // pop rdi
                0x5E,                                                       // pop rsi
                0x5D,                                                       // pop rbp
                0x5B,                                                       // pop rbx
                0x5A,                                                       // pop rdx
                0x59,                                                       // pop rcx
                0x9D,                                                       // popf
                0x58,                                                       // pop rax
                0xC3                                                        // ret
            };

            // Copy the pointers into the shellcode

            var instructionPointerBytes = BitConverter.GetBytes((ulong) instructionPointer);

            var dllPathAddressBytes = BitConverter.GetBytes((ulong) dllPathAddress);

            var loadLibraryAddressBytes = BitConverter.GetBytes((ulong) loadLibraryAddress);

            Buffer.BlockCopy(instructionPointerBytes, 0, shellcode, 3, 8);

            Buffer.BlockCopy(dllPathAddressBytes, 0, shellcode, 41, 8);

            Buffer.BlockCopy(loadLibraryAddressBytes, 0, shellcode, 51, 8);

            return shellcode;
        }
    }
}
