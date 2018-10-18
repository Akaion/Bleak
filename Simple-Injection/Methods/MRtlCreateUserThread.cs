using System;
using System.Diagnostics;
using System.Text;
using static Simple_Injection.Etc.Native;

namespace Simple_Injection.Methods
{
    public static class MRtlCreateUserThread
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
            
            var userThreadHandle = RtlCreateUserThread(processHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, loadLibraryPointer ,dllMemoryPointer, IntPtr.Zero, IntPtr.Zero);
            
            if (userThreadHandle == IntPtr.Zero)
            {
                return false;
            }
            
            // Wait for the user thread to finish
            
            WaitForSingleObject(userThreadHandle, 0xFFFFFFFF);
            
            // Free the previously allocated memory
            
            VirtualFreeEx(processHandle, dllMemoryPointer, dllNameSize, MemoryAllocation.Release);
            
            // Close the previously opened handles
            
            CloseHandle(processHandle);
            CloseHandle(userThreadHandle);
            
            return true;
        }
    }
}