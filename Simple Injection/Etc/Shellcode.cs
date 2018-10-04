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
        
        
    }
}