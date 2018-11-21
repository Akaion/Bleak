using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Simple_Injection.Etc;
using static Simple_Injection.Etc.Native;
using static Simple_Injection.Etc.Wrapper;

namespace Simple_Injection.Methods
{
    internal static class MSetThreadContext
    { 
        internal static bool Inject(string dllPath, string processName)
        {
            // Ensure both arguments passed in are valid
            
            if (string.IsNullOrEmpty(dllPath) || string.IsNullOrEmpty(processName))
            {
                return false;
            }
            
            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                return false;
            }
            
            // Determine whether compiled as x86 or x64
            
            var compiledAsx64 = Environment.Is64BitProcess;
            
            // Cache an instance of the specified process

            Process process;
            
            try
            {
                process = Process.GetProcessesByName(processName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                return false;
            }
            
            // Get the pointer to load library

            var loadLibraryPointer = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");

            if (loadLibraryPointer == IntPtr.Zero)
            {
                return false;
            }

            // Get the handle of the specified process

            var processHandle = process.SafeHandle;

            if (processHandle == null)
            {
                return false;
            }
            
            // Allocate memory for the dll name

            var dllNameSize = dllPath.Length;

            var dllMemoryPointer = VirtualAllocEx(processHandle, IntPtr.Zero, dllNameSize, MemoryAllocation.AllAccess, MemoryProtection.PageExecuteReadWrite);
      
            if (dllMemoryPointer == IntPtr.Zero)
            {
                return false;
            }
            
            // Allocate memory for the shellcode

            var shellcodeSize = compiledAsx64 ? 87 : 22;

            var shellcodeMemoryPointer = VirtualAllocEx(processHandle, IntPtr.Zero, shellcodeSize, MemoryAllocation.AllAccess, MemoryProtection.PageExecuteReadWrite);      
            
            // Write the dll name into memory

            var dllBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

            if (!WriteMemory(processHandle, dllMemoryPointer, dllBytes))
            {
                return false;
            }
            
            // Get the handle of the first thread in the specified process
            
            var threadId = process.Threads[0].Id;
            
            var threadHandle = OpenThread(ThreadAccess.AllAccess, false, threadId);

            if (threadHandle == IntPtr.Zero)
            {
                return false;
            }
            
            // Suspend the thread

            SuspendThread(threadHandle);
             
            if (compiledAsx64)
            {
                if (!SetThreadContextx64(threadHandle, processHandle, dllMemoryPointer, loadLibraryPointer, shellcodeMemoryPointer))
                {
                    return false;
                }
            }

            else
            {
                if (!SetThreadContextx86(threadHandle, processHandle, dllMemoryPointer, loadLibraryPointer, shellcodeMemoryPointer))
                {
                    return false;
                }
            }
            
            // Resume the thread

            ResumeThread(threadHandle);

            // Simulate a keypress to execute the dll
            
            PostMessage(process.MainWindowHandle, WindowsMessage.WmKeydown, (IntPtr) 0x01, IntPtr.Zero);
            
            // Free the previously allocated memory

            VirtualFreeEx(processHandle, dllMemoryPointer, dllNameSize, MemoryAllocation.Release);
            
            VirtualFreeEx(processHandle, shellcodeMemoryPointer, shellcodeSize, MemoryAllocation.Release);
            
            // Close the previously opened handle
            
            CloseHandle(threadHandle);
            
            return true;
        }
        
        internal static bool Inject(string dllPath, int processId)
        {
            // Ensure both arguments passed in are valid
            
            if (string.IsNullOrEmpty(dllPath) || processId == 0)
            {
                return false;
            }
            
            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                return false;
            }
            
            // Determine whether compiled as x86 or x64
            
            var compiledAsx64 = Environment.Is64BitProcess;
            
            // Cache an instance of the specified process

            Process process;
            
            try
            {
                process = Process.GetProcessById(processId);
            }

            catch (IndexOutOfRangeException)
            {
                return false;
            }
            
            // Get the pointer to load library

            var loadLibraryPointer = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");

            if (loadLibraryPointer == IntPtr.Zero)
            {
                return false;
            }

            // Get the handle of the specified process

            var processHandle = process.SafeHandle;

            if (processHandle == null)
            {
                return false;
            }
            
            // Allocate memory for the dll name

            var dllNameSize = dllPath.Length;

            var dllMemoryPointer = VirtualAllocEx(processHandle, IntPtr.Zero, dllNameSize, MemoryAllocation.AllAccess, MemoryProtection.PageExecuteReadWrite);
      
            if (dllMemoryPointer == IntPtr.Zero)
            {
                return false;
            }
            
            // Allocate memory for the shellcode

            var shellcodeSize = compiledAsx64 ? 87 : 22;

            var shellcodeMemoryPointer = VirtualAllocEx(processHandle, IntPtr.Zero, shellcodeSize, MemoryAllocation.AllAccess, MemoryProtection.PageExecuteReadWrite);      
            
            // Write the dll name into memory

            var dllBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

            if (!WriteMemory(processHandle, dllMemoryPointer, dllBytes))
            {
                return false;
            }
            
            // Get the handle of the first thread in the specified process
            
            var threadId = process.Threads[0].Id;
            
            var threadHandle = OpenThread(ThreadAccess.AllAccess, false, threadId);

            if (threadHandle == IntPtr.Zero)
            {
                return false;
            }
            
            // Suspend the thread

            SuspendThread(threadHandle);
             
            if (compiledAsx64)
            {
                if (!SetThreadContextx64(threadHandle, processHandle, dllMemoryPointer, loadLibraryPointer, shellcodeMemoryPointer))
                {
                    return false;
                }
            }

            else
            {
                if (!SetThreadContextx86(threadHandle, processHandle, dllMemoryPointer, loadLibraryPointer, shellcodeMemoryPointer))
                {
                    return false;
                }
            }
            
            // Resume the thread

            ResumeThread(threadHandle);

            // Simulate a keypress to execute the dll
            
            PostMessage(process.MainWindowHandle, WindowsMessage.WmKeydown, (IntPtr) 0x01, IntPtr.Zero);
            
            // Free the previously allocated memory

            VirtualFreeEx(processHandle, dllMemoryPointer, dllNameSize, MemoryAllocation.Release);
            
            VirtualFreeEx(processHandle, shellcodeMemoryPointer, shellcodeSize, MemoryAllocation.Release);
            
            // Close the previously opened handle
            
            CloseHandle(threadHandle);
            
            return true;
        }
        
        private static bool SetThreadContextx86(IntPtr threadHandle, SafeHandle processHandle, IntPtr dllMemoryPointer, IntPtr loadLibraryPointer, IntPtr shellcodeMemoryPointer)
        {
            // Get the threads context

            var context = new Context {Flags = ContextFlags.ContextControl};

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
      
        private static bool SetThreadContextx64(IntPtr threadHandle, SafeHandle processHandle, IntPtr dllMemoryPointer, IntPtr loadLibraryPointer, IntPtr shellcodeMemoryPointer)
        {
            // Get the threads context

            var context = new Context64 {Flags = ContextFlags.ContextControl};

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