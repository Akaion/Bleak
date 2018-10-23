using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using Simple_Injection.Extensions;
using static Simple_Injection.Etc.Native;

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
            
            // Write the dll name into memory

            var dllBytes = Encoding.Default.GetBytes(dllPath);

            if (!WriteProcessMemory(processHandle, dllMemoryPointer, dllBytes, (uint) dllNameSize, 0))
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
            
            VirtualFreeEx(processHandle, dllMemoryPointer, (uint) dllNameSize, MemoryAllocation.Release);
                    
            // Close the previously opened handle

            CloseHandle(userThreadHandle);
            
            return true;
        }
    }
}