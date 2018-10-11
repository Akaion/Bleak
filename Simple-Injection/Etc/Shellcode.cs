using System;

namespace Simple_Injection.Etc
{
    public static class Shellcode
    {
        public static byte[] CallLoadLibraryx86(uint instructionPointer, IntPtr dllMemoryPointer, IntPtr loadLibraryPointer)
        {
            var shellcode = new byte[]
            {
                0x68, 0x00, 0x00, 0x00, 0x00, // push 0x00000000
                0x9C,                         // pushfd
                0x60,                         // pushad
                0x68, 0x00, 0x00, 0x00, 0x00, // push 0x00000000 
                0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00000000
                0xFF, 0xD0,                   // call eax
                0x61,                         // popad
                0x9D,                         // popfd
                0xC3                          // ret
            };

            // Get the byte representation of each pointer
            
            var instructionPointerBytes = BitConverter.GetBytes(instructionPointer);

            var memoryPointerBytes = BitConverter.GetBytes((uint) dllMemoryPointer);

            var loadLibraryPointerBytes = BitConverter.GetBytes((uint) loadLibraryPointer);
            
            // Write the pointers into the shellcode
            
            Buffer.BlockCopy(instructionPointerBytes, 0, shellcode, 1, 4);
            Buffer.BlockCopy(memoryPointerBytes, 0, shellcode, 8, 4);
            Buffer.BlockCopy(loadLibraryPointerBytes, 0, shellcode, 13, 4);
            
            return shellcode;
        }

        public static byte[] CallLoadLibraryx64(ulong instructionPointer, IntPtr dllMemoryPointer, IntPtr loadLibraryPointer)
        {
            var shellcode = new byte[]
            {
                0x50,                                                       // push rax
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0000000000000000
                0x9c,                                                       // pushfq
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
                0x68, 0x00, 0x00, 0x00, 0x00,                               // fastcall convention
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0000000000000000 
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0000000000000000 
                0xFF, 0xD0,                                                 // call rax
                0x58,                                                       // pop dummy
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
                0x9D,                                                       // popfq
                0x58,                                                       // pop rax
                0xC3                                                        // ret

            };

            // Get the byte representation of each pointer

            var instructionPointerBytes = BitConverter.GetBytes(instructionPointer);

            var memoryPointerBytes = BitConverter.GetBytes((ulong) dllMemoryPointer);

            var loadLibraryPointerBytes = BitConverter.GetBytes((ulong) loadLibraryPointer);
            
            // Write the pointers into the shellcode
            
            Buffer.BlockCopy(instructionPointerBytes, 0, shellcode, 3, 8);
            Buffer.BlockCopy(memoryPointerBytes, 0, shellcode, 41, 8);
            Buffer.BlockCopy(loadLibraryPointerBytes, 0, shellcode, 51, 8);

            return shellcode;
        }
        
    }
}