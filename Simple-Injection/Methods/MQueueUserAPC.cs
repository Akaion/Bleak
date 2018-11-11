using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using static Simple_Injection.Etc.Native;
using static Simple_Injection.Etc.Wrapper;

namespace Simple_Injection.Methods
{
    public static class MQueueUserAPC
    {
        public static bool Inject(string dllPath, string processName)
        {
            // Ensure both arguments passed in are valid
            
            if (string.IsNullOrEmpty(dllPath) || string.IsNullOrEmpty(processName))
            {
                return false;
            }
            
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

            var loadLibraryPointer = GetLoadLibraryAddress();

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

            var dllMemoryPointer = AllocateMemory(processHandle, dllNameSize);

            if (dllMemoryPointer == IntPtr.Zero)
            {
                return false;
            }
            
            // Write the dll name into memory

            var dllBytes = Encoding.Default.GetBytes(dllPath);

            if (!WriteMemory(processHandle, dllMemoryPointer, dllBytes))
            {
                return false;
            }

            // Call QueueUserAPC on each thread
            
            foreach (var thread in Process.GetProcessesByName(processName)[0].Threads.Cast<ProcessThread>())
            {
                var threadId = thread.Id;
                
                // Get the threads handle
                
                var threadHandle = OpenThread(ThreadAccess.AllAccess, false, threadId);

                // Add a user-mode APC to the APC queue of the thread
                
                QueueUserAPC(loadLibraryPointer, threadHandle, dllMemoryPointer);
                
                // Close the handle to the thread
                
                CloseHandle(threadHandle);
            }
            
            // Free the previously allocated memory
            
            FreeMemory(processHandle, dllMemoryPointer, dllNameSize);
            
            return true;
        }  
    }
}