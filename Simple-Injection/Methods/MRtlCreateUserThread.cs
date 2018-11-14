using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static Simple_Injection.Etc.Native;
using static Simple_Injection.Etc.Wrapper;

namespace Simple_Injection.Methods
{
    internal static class MRtlCreateUserThread
    {
        internal static bool Inject(string dllPath, string processName)
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
            
            // Write the dll name into memory

            var dllBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

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
            
            VirtualFreeEx(processHandle, dllMemoryPointer, dllNameSize, MemoryAllocation.Release);
                    
            // Close the previously opened handle

            CloseHandle(userThreadHandle);
            
            return true;
        }
    }
}