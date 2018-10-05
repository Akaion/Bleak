using System;
using System.Diagnostics;
using System.Text;
using Simple_Injection.Etc;
using static Simple_Injection.Etc.Native;

namespace Simple_Injection.Methods
{
    public static class MSetThreadContext
    {
        public static bool Inject(string dllPath, string processName)
        {
            // Get the pointer to load library

            var loadLibraryPointer = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            if (loadLibraryPointer == IntPtr.Zero)
            {
                return false;
            }
            
            // Get the handle of the specified process
            
            var processId = Process.GetProcessesByName(processName)[0].Id;
            
            var processHandle = OpenProcess(ProcessPrivileges.AllAccess, false, processId);
            
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

            const int shellcodeSize = 22;
            
            var shellcodeMemoryPointer = VirtualAllocEx(processHandle, IntPtr.Zero, shellcodeSize, MemoryAllocation.Commit, MemoryProtection.PageExecuteReadWrite);
            
            // Write the dll name into memory

            var dllBytes = Encoding.Default.GetBytes(dllPath);

            if (!WriteProcessMemory(processHandle, dllMemoryPointer, dllBytes, (uint) dllNameSize, 0))
            {
                return false;
            }
            
            // Get the handle of the first thread of the specified process
            
            var threadId = Process.GetProcessesByName(processName)[0].Threads[0].Id;

            var threadHandle = OpenThread(ThreadAccess.AllAccess, false, (uint) threadId);
            
            // Suspend the thread

            SuspendThread(threadHandle);
            
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

            if (!WriteProcessMemory(processHandle, shellcodeMemoryPointer, shellcode, shellcodeSize, 0))
            {
                return false;
            }
            
            // Set the threads context

            if (!SetThreadContext(threadHandle, ref context))
            {
                return false;
            }
            
            // Resume the thread

            ResumeThread(threadHandle);

            // Free the previously allocated memory
            
            VirtualFreeEx(processHandle, dllMemoryPointer, dllNameSize, MemoryAllocation.Release);
            VirtualFreeEx(processHandle, shellcodeMemoryPointer, shellcodeSize, MemoryAllocation.Release);
            
            // Close the previously opened handles
            
            CloseHandle(processHandle);
            CloseHandle(threadHandle);
            
            return true;
        }
    }
}