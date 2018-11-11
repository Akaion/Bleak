using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static Simple_Injection.Etc.Native;
using static Simple_Injection.Etc.Wrapper;

namespace Simple_Injection.Methods
{
    public static class MRtlCreateUserThread
    {
        public static bool Inject(string dllPath, string processName)
        {
            // Ensure both arguments passed in are valid
            
            if (string.IsNullOrEmpty(dllPath) || string.IsNullOrEmpty(processName))
            {
                return false;
            }
            
            // Cache an instance of the specified process

            var process = Process.GetProcessesByName(processName)[0];

            if (process == null)
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

            var processHandle = process.Handle;

            if (processHandle == IntPtr.Zero)
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
                       
            // Create a user thread to call load library in the specified process
            
            RtlCreateUserThread(processHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, loadLibraryPointer , dllMemoryPointer, out var userThreadHandle, IntPtr.Zero);
            
            if (userThreadHandle == IntPtr.Zero)
            {
                return false;
            }
            
            // Wait for the user thread to finish
            
            WaitForSingleObject(userThreadHandle, 0xFFFFFFFF);
            
            // Free the previously allocated memory
            
            FreeMemory(processHandle, dllMemoryPointer, dllNameSize);
                    
            // Close the previously opened handle

            CloseHandle(userThreadHandle);
            
            return true;
        }
    }
}