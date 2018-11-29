using System;

namespace Simple_Injection.Etc
{
    internal static class Shellcode
    {
        internal static byte[] CallLoadLibraryx86(IntPtr instructionPointer, IntPtr dllNameAddress, IntPtr loadLibraryAddress)
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

            var instructionPointerBytes = BitConverter.GetBytes((int) instructionPointer);

            var dllMemoryPointerBytes = BitConverter.GetBytes((int) dllNameAddress);

            var loadLibraryPointerBytes = BitConverter.GetBytes((int) loadLibraryAddress);

            // Write the pointers into the shellcode

            Buffer.BlockCopy(instructionPointerBytes, 0, shellcode, 1, 4);
            
            Buffer.BlockCopy(dllMemoryPointerBytes, 0, shellcode, 8, 4);
            
            Buffer.BlockCopy(loadLibraryPointerBytes, 0, shellcode, 13, 4);

            return shellcode;
        }

        internal static byte[] CallLoadLibraryx64(IntPtr instructionPointer, IntPtr dllNameAddress, IntPtr loadLibraryAddress)
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

            var instructionPointerBytes = BitConverter.GetBytes((long) instructionPointer);

            var dllNameAddressBytes = BitConverter.GetBytes((long) dllNameAddress);

            var loadLibraryAddressBytes = BitConverter.GetBytes((long) loadLibraryAddress);

            // Write the pointers into the shellcode

            Buffer.BlockCopy(instructionPointerBytes, 0, shellcode, 3, 8);
            
            Buffer.BlockCopy(dllNameAddressBytes, 0, shellcode, 41, 8);
            
            Buffer.BlockCopy(loadLibraryAddressBytes, 0, shellcode, 51, 8);

            return shellcode;
        }

        internal static byte[] CallDllMainx86(IntPtr baseAddress, IntPtr entryPointAddress)
        {
            var shellcode = new byte[]
            {
                0x68, 0x00, 0x00, 0x00, 0x00, // push 0x00000000
                0x68, 0x01, 0x00, 0x00, 0x00, // push 0x00000001
                0x68, 0x00, 0x00, 0x00, 0x00, // push 0x00000000
                0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x00000000
                0xFF, 0xD0,                   // call eax
                0x33, 0xC0,                   // xor eax, eax
                0xC3                          // ret
            };

            // Get the byte representation of each pointer
            
            var baseAddressBytes = BitConverter.GetBytes((int) baseAddress);

            var entryPointAddressBytes = BitConverter.GetBytes((int) entryPointAddress);

            // Write the pointers into the shellcode

            Buffer.BlockCopy(baseAddressBytes, 0, shellcode, 1, 4);
            
            Buffer.BlockCopy(entryPointAddressBytes, 0, shellcode, 16, 4);

            return shellcode;
        }

        internal static byte[] CallDllMainx64(IntPtr baseAddress, IntPtr entryPointAddress)
        {
            var shellcode = new byte[]
            {
                0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0x0000000000000000
                0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,                   // mov rdx, 0x1
                0x4D, 0x31, 0xC0,                                           // xor r8, r8
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x0000000000000000
                0xFF, 0xD0,                                                 // call rax
                0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
                0x31, 0xC0,                                                 // xor eax, eax
                0xC3                                                        // ret
            };

            // Get the byte representation of each pointer
            
            var baseAddressBytes = BitConverter.GetBytes((long) baseAddress);

            var entryPointAddressBytes = BitConverter.GetBytes((long) entryPointAddress);

            // Write the pointers into the shellcode

            Buffer.BlockCopy(baseAddressBytes, 0, shellcode, 6, 4);
            
            Buffer.BlockCopy(entryPointAddressBytes, 0, shellcode, 26, 4);

            return shellcode;
        }
    }
}