using System;
using System.Runtime.InteropServices;
using static Simple_Injection.Etc.Native;

namespace Simple_Injection.Etc
{
    internal static class Wrapper
    {             
        internal static bool WriteMemory(SafeHandle processHandle, IntPtr memoryPointer, byte[] buffer)
        {
            // Change the protection of the memory region

            if (!VirtualProtectEx(processHandle, memoryPointer, buffer.Length, 0x40, out var oldProtection))
            {
                return false;
            }

            // Write the buffer into the memory region

            if (!WriteProcessMemory(processHandle, memoryPointer, buffer, buffer.Length, 0))
            {
                return false;
            }

            // Restore the protection of the memory region

            if (!VirtualProtectEx(processHandle, memoryPointer, buffer.Length, oldProtection, out _))
            {
                return false;
            }

            return true;
        }
        
        internal static bool SetThreadContextx86(IntPtr threadHandle, SafeHandle processHandle, IntPtr dllMemoryPointer, IntPtr loadLibraryPointer, IntPtr shellcodeMemoryPointer)
        {
            // Get the threads context

            var context = new Context {ContextFlags = (uint) Flags.ContextControl};

            if (!GetThreadContext(threadHandle, ref context))
            {
                return false;
            }
            
            // Save the instruction pointer

            var instructionPointer = context.Eip;
            
            // Change the instruction pointer to the shellcode pointer

            context.Eip = shellcodeMemoryPointer;
            
            // Write the shellcode into memory

            var shellcode = Shellcode.CallLoadLibraryx86(instructionPointer, dllMemoryPointer, loadLibraryPointer);

            if (!WriteMemory(processHandle, shellcodeMemoryPointer, shellcode))
            {
                return false;
            }
            
            // Set the threads context

            if (!SetThreadContext(threadHandle, ref context))
            {
                return false;
            }
            
            return true;
        }
        
        internal static bool SetThreadContextx64(IntPtr threadHandle, SafeHandle processHandle, IntPtr dllMemoryPointer, IntPtr loadLibraryPointer, IntPtr shellcodeMemoryPointer)
        {
            // Get the threads context

            var context = new Context64 {ContextFlags = Flags.ContextControl};

            if (!GetThreadContext(threadHandle, ref context))
            {
                return false;
            }
            
            // Save the instruction pointer

            var instructionPointer = context.Rip;
            
            // Change the instruction pointer to the shellcode pointer

            context.Rip = shellcodeMemoryPointer;
            
            // Write the shellcode into memory

            var shellcode = Shellcode.CallLoadLibraryx64(instructionPointer, dllMemoryPointer, loadLibraryPointer);

            if (!WriteMemory(processHandle, shellcodeMemoryPointer, shellcode))
            {
                return false;
            }
            
            // Set the threads context

            if (!SetThreadContext(threadHandle, ref context))
            {
                return false;
            }
            
            return true;
        }
    }
}