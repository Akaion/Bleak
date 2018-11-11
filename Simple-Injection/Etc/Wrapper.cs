using System;
using System.Runtime.InteropServices;
using static Simple_Injection.Etc.Native;

namespace Simple_Injection.Etc
{
    public static class Wrapper
    {
        public static IntPtr GetLoadLibraryAddress()
        {
            // Get the pointer to load library
            
            return GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        } 
        
        public static IntPtr AllocateMemory(SafeHandle processHandle, int size)
        {
            // Allocate memory in specified process
            
            return VirtualAllocEx(processHandle, IntPtr.Zero, size, MemoryAllocation.AllAccess, MemoryProtection.PageExecuteReadWrite);
        }
        
        public static bool WriteMemory(SafeHandle processHandle, IntPtr memoryPointer, byte[] buffer)
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

        public static void FreeMemory(SafeHandle processHandle, IntPtr memoryPointer, int size)
        {
            // Free memory at specified address
            
            VirtualFreeEx(processHandle, memoryPointer, size, MemoryAllocation.Release);
        }
        
        public static bool SetThreadContextx86(IntPtr threadHandle, SafeHandle processHandle, IntPtr dllMemoryPointer, IntPtr loadLibraryPointer, IntPtr shellcodeMemoryPointer)
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

            context.Eip = (uint) shellcodeMemoryPointer;
            
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
        
        public static bool SetThreadContextx64(IntPtr threadHandle, SafeHandle processHandle, IntPtr dllMemoryPointer, IntPtr loadLibraryPointer, IntPtr shellcodeMemoryPointer)
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

            context.Rip = (ulong) shellcodeMemoryPointer;
            
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