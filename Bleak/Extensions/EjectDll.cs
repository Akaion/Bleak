using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using PeNet;
using static Bleak.Etc.Native;

namespace Bleak.Extensions
{
    internal static class EjectDll
    {
        internal static bool Eject(string dllPath, string processName)
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

            // Eject the dll

            return Eject(dllPath, process);            
        }
        
        internal static bool Eject(string dllPath, int processId)
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

            // Eject the dll

            return Eject(dllPath, process);
        }
        
        private static bool Eject(string dllPath, Process process)
        {
            // Get the address of the free library method

            var freeLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary");

            if (freeLibraryAddress == IntPtr.Zero)
            {
                return false;
            }

            // Get a handle to the specified process

            var processHandle = process.SafeHandle;

            if (processHandle == null)
            {
                return false;
            }

            // Get the name of the dll

            var dllName = Path.GetFileName(dllPath);
            
            // Get an instance of the dll in the process
            
            var module = process.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, dllName, StringComparison.OrdinalIgnoreCase));

            if (module == null)
            {
                return false;
            }

            // Get the dll base address
            
            var dllBaseAddress = module.BaseAddress;
            
            if (dllBaseAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Create a user thread to call free library in the specified process
            
            RtlCreateUserThread(processHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, freeLibraryAddress, dllBaseAddress, out var userThreadHandle, IntPtr.Zero);
            
            if (userThreadHandle == IntPtr.Zero)
            {
                return false;
            }
            
            // Wait for the user thread to finish

            WaitForSingleObject(userThreadHandle, int.MaxValue);
            
            // Close the previously opened handle

            CloseHandle(userThreadHandle);
            
            return true;
        }
    }
}