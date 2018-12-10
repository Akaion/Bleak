using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using PeNet;
using static Bleak.Etc.Native;
using static Bleak.Etc.Wrapper;

namespace Bleak.Methods
{
    internal static class QueueUserApc
    {
        internal static bool Inject(string dllPath, string processName)
        {
            // Ensure parameters are valid

            if (string.IsNullOrEmpty(dllPath) || string.IsNullOrEmpty(processName))
            {
                return false;
            }

            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                return false;
            }
            
            // Get the pe headers

            var peHeaders = new PeFile(dllPath);
            
            // Ensure the dll architecture is the same as the compiled architecture

            if (peHeaders.Is64Bit != Environment.Is64BitProcess)
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

            return Inject(dllPath, process);
        }

        internal static bool Inject(string dllPath, int processId)
        {
            // Ensure parameters are valid

            if (string.IsNullOrEmpty(dllPath) || processId == 0)
            {
                return false;
            }

            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                return false;
            }
            
            // Get the pe headers

            var peHeaders = new PeFile(dllPath);
            
            // Ensure the dll architecture is the same as the compiled architecture

            if (peHeaders.Is64Bit != Environment.Is64BitProcess)
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

            // Call QueueUserAPC on each thread

            foreach (var thread in process.Threads.Cast<ProcessThread>())
            {
                // Open a handle to the thread

                var threadHandle = OpenThread(ThreadAccess.SetContext, false, thread.Id);

                // Add a user-mode APC to the APC queue of the thread

                QueueUserAPC(loadLibraryAddress, threadHandle, dllPathAddress);

                // Close the previously opened handle

                CloseHandle(threadHandle);
            }

            // Free the previously allocated memory

            VirtualFreeEx(processHandle, dllPathAddress, dllPathSize, MemoryAllocation.Release);

            return true;
        }
    }
}