using System;
using System.Diagnostics;
using System.Text;
using static Simple_Injection.Etc.Native;
using static Simple_Injection.Etc.Wrapper;

namespace Simple_Injection.Methods
{
    public static class MCreateRemoteThread
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
            
            // Create a remote thread to call load library in the specified process

            var remoteThreadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryPointer, dllMemoryPointer, 0, IntPtr.Zero);

            if (remoteThreadHandle == IntPtr.Zero)
            {
                return false;
            }
            
            // Wait for the remote thread to finish
            
            WaitForSingleObject(remoteThreadHandle, 0xFFFFFFFF);
            
            // Free the previously allocated memory
            
            FreeMemory(processHandle, dllMemoryPointer, dllNameSize);
            
            // Close the previously opened handle
            
            CloseHandle(remoteThreadHandle);
            
            return true;
        }
    }
}