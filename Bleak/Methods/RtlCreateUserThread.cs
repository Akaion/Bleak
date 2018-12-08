using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using static Bleak.Etc.Native;
using static Bleak.Etc.Wrapper;

namespace Bleak.Methods
{
     internal static class RtlCreateUserThread
    {
        internal static bool Inject(string dllPath, string processName)
        {
            // Ensure both parameters are valid

            if (string.IsNullOrEmpty(dllPath) || string.IsNullOrEmpty(processName))
            {
                return false;
            }

            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                return false;
            }

            // Get an instance of the specified process

            Process process;

            try
            {
                process = Process.GetProcessesByName(processName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                return false;
            }

            // Inject the dll

            return Inject(dllPath, process);
        }

        internal static bool Inject(string dllPath, int processId)
        {
            // Ensure both parameters are valid

            if (string.IsNullOrEmpty(dllPath) || processId == 0)
            {
                return false;
            }

            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                return false;
            }

            // Get an instance of the specified process

            Process process;

            try
            {
                process = Process.GetProcessById(processId);
            }

            catch (IndexOutOfRangeException)
            {
                return false;
            }

            // Inject the dll

            return Inject(dllPath, process);
        }

        private static bool Inject(string dllPath, Process process)
        {
            // Get the address of the load library method

            var loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");

            if (loadLibraryAddress == IntPtr.Zero)
            {
                return false;
            }

            // Get a handle to the specified process

            var processHandle = process.SafeHandle;

            if (processHandle == null)
            {
                return false;
            }

            // Allocate memory for the dll path

            var dllPathSize = dllPath.Length;

            var dllPathAddress = VirtualAllocEx(processHandle, IntPtr.Zero, dllPathSize, MemoryAllocation.Commit | MemoryAllocation.Reserve, MemoryProtection.PageExecuteReadWrite);

            if (dllPathAddress == IntPtr.Zero)
            {
                return false;
            }

            // Write the dll path into memory

            var dllPathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

            if (!WriteMemory(processHandle, dllPathAddress, dllPathBytes))
            {
                return false;
            }

            // Create a user thread to call load library in the specified process

            RtlCreateUserThread(processHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, loadLibraryAddress, dllPathAddress, out var userThreadHandle, IntPtr.Zero);

            if (userThreadHandle == IntPtr.Zero)
            {
                return false;
            }

            // Wait for the user thread to finish

            WaitForSingleObject(userThreadHandle, int.MaxValue);

            // Free the previously allocated memory

            VirtualFreeEx(processHandle, dllPathAddress, dllPathSize, MemoryAllocation.Release);

            // Close the previously opened handle

            CloseHandle(userThreadHandle);

            return true;
        }
    }
}