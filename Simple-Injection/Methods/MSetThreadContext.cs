using System;
using System.Diagnostics;
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

            var dllNameSize = dllPath.Length + 1;

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
    }
}