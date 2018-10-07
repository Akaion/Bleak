using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using static Simple_Injection.Etc.Native;

namespace Simple_Injection.Methods
{
    public static class MQueueUserAPC
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
            
            // Write the dll name into memory

            var dllBytes = Encoding.Default.GetBytes(dllPath);

            if (!WriteProcessMemory(processHandle, dllMemoryPointer, dllBytes, (uint) dllNameSize, 0))
            {
                return false;
            }

            // Call QueueUserAPC on each thread
            
            foreach (var thread in Process.GetProcessesByName(processName)[0].Threads.Cast<ProcessThread>())
            {
                var threadId = thread.Id;
                
                // Get the threads handle
                
                var threadHandle = OpenThread(ThreadAccess.SetContext, false, (uint) threadId);

                // Add a user-mode APC to the APC queue of the thread
                
                QueueUserAPC(loadLibraryPointer, threadHandle, dllMemoryPointer);
                
                // Close the handle to the thread
                
                CloseHandle(threadHandle);
            }
            
            // Close the previously opened handle
            
            CloseHandle(processHandle);
            
            // Free the previously allocated memory
            
            VirtualFreeEx(processHandle, dllMemoryPointer, dllNameSize, MemoryAllocation.Release);
            
            return true;
        }  
    }
}