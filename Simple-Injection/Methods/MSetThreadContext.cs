using System;
using System.Diagnostics;
using System.Text;
using Simple_Injection.Etc;
using static Simple_Injection.Etc.Native;

namespace Simple_Injection.Methods
{
    public static class MSetThreadContext
    {
        private static bool SetThreadContextx86(IntPtr threadHandle, IntPtr processHandle, IntPtr dllMemoryPointer, IntPtr loadLibraryPointer, IntPtr shellcodeMemoryPointer, int shellcodeSize)
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

            if (!WriteProcessMemory(processHandle, shellcodeMemoryPointer, shellcode, (uint) shellcodeSize, 0))
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
        
        private static bool SetThreadContextx64(IntPtr threadHandle, IntPtr processHandle, IntPtr dllMemoryPointer, IntPtr loadLibraryPointer, IntPtr shellcodeMemoryPointer, int shellcodeSize)
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

            if (!WriteProcessMemory(processHandle, shellcodeMemoryPointer, shellcode, (uint) shellcodeSize, 0))
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
        
        public static bool Inject(string dllPath, string processName)
        {
            // Determine whether compiled as x86 or x64
            
            var compiledAsx64 = Environment.Is64BitProcess;
            
            // Cache an instance of the specified process

            var process = Process.GetProcessesByName(processName)[0];
            
            // Get the pointer to load library

            var loadLibraryPointer = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            if (loadLibraryPointer == IntPtr.Zero)
            {
                return false;
            }

            // Get the handle of the specified process

            var processHandle = process.Handle;

            if (processHandle == IntPtr.Zero)
            {
                return false;
            }
            
            // Allocate memory for the dll name

            var dllNameSize = dllPath.Length + 1;

            var dllMemoryPointer = VirtualAllocEx(processHandle, IntPtr.Zero, (uint) dllNameSize, MemoryAllocation.AllAccess, MemoryProtection.PageReadWrite);

            if (dllMemoryPointer == IntPtr.Zero)
            {
                return false;
            }
            
            // Allocate memory for the shellcode

            var shellcodeSize = compiledAsx64 ? 87 : 22;
            
            var shellcodeMemoryPointer = VirtualAllocEx(processHandle, IntPtr.Zero, (uint) shellcodeSize, MemoryAllocation.Commit, MemoryProtection.PageExecuteReadWrite);
            
            // Write the dll name into memory

            var dllBytes = Encoding.Default.GetBytes(dllPath);

            if (!WriteProcessMemory(processHandle, dllMemoryPointer, dllBytes, (uint) dllNameSize, 0))
            {
                return false;
            }
            
            // Get the handle of the first thread of the specified process
            
            var threadId = process.Threads[0].Id;

            var threadHandle = OpenThread(ThreadAccess.AllAccess, false, (uint) threadId);

            if (threadHandle == IntPtr.Zero)
            {
                return false;
            }
            
            // Suspend the thread

            SuspendThread(threadHandle);
             
            if (compiledAsx64)
            {
                if (!SetThreadContextx64(threadHandle, processHandle, dllMemoryPointer, loadLibraryPointer, shellcodeMemoryPointer, shellcodeSize))
                {
                    return false;
                }
            }

            else
            {
                if (!SetThreadContextx86(threadHandle, processHandle, dllMemoryPointer, loadLibraryPointer, shellcodeMemoryPointer, shellcodeSize))
                {
                    return false;
                }
            }
            
            // Resume the thread

            ResumeThread(threadHandle);

            // Free the previously allocated memory
            
            VirtualFreeEx(processHandle, dllMemoryPointer, dllNameSize, MemoryAllocation.Release);
            VirtualFreeEx(processHandle, shellcodeMemoryPointer, shellcodeSize, MemoryAllocation.Release);
            
            // Close the previously opened handle
            
            CloseHandle(threadHandle);
            
            return true;
        }
    }
}