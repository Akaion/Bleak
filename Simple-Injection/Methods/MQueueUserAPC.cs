using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using static Simple_Injection.Etc.Native;
using static Simple_Injection.Etc.Wrapper;

namespace Simple_Injection.Methods
{
    internal static class MQueueUserAPC
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
            
            // Write the dll name into memory

            var dllBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

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
            
            VirtualFreeEx(processHandle, dllMemoryPointer, dllNameSize, MemoryAllocation.Release);
            
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
            
            // Write the dll name into memory

            var dllBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

            if (!WriteMemory(processHandle, dllMemoryPointer, dllBytes))
            {
                return false;
            }

            // Call QueueUserAPC on each thread
            
            foreach (var thread in Process.GetProcessById(processId).Threads.Cast<ProcessThread>())
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
            
            VirtualFreeEx(processHandle, dllMemoryPointer, dllNameSize, MemoryAllocation.Release);
            
            return true;
        } 
    }
}