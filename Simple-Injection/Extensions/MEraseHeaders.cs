using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static Simple_Injection.Etc.Native;
using static Simple_Injection.Etc.Wrapper;

namespace Simple_Injection.Extensions
{
    internal static class MEraseHeaders
    {
        internal static bool Erase(string dllPath, string processName)
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

            // Get the handle of the specified process

            var processHandle = process.SafeHandle;

            if (processHandle == null)
            {
                return false;
            }
                   
            var moduleBaseAddress = IntPtr.Zero;

            // Find the injected dll base address
            
            foreach (var module in process.Modules.Cast<ProcessModule>())
            {
                if (module.ModuleName == Path.GetFileName(dllPath))
                {
                    moduleBaseAddress = module.BaseAddress;

                    break;
                }
            }
            
            if (moduleBaseAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Get the information about the header region of the module

            var memoryInformationSize = Marshal.SizeOf(typeof(MemoryBasicInformation));

            if (!VirtualQueryEx(processHandle, moduleBaseAddress, out var memoryInformation, memoryInformationSize))
            {
                return false;
            }

            // Generate a buffer to write over the header region with
            
            var buffer = new byte[(int) memoryInformation.RegionSize];

            // Write over the header region

            if (!WriteMemory(processHandle, moduleBaseAddress, buffer))
            {
                return false;
            }

            return true;
        }
        
        internal static bool Erase(string dllPath, int processId)
        {
            // Ensure both arguments passed in are valid
            
            if (string.IsNullOrEmpty(dllPath) || processId == 0)
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

            // Get the handle of the specified process

            var processHandle = process.SafeHandle;

            if (processHandle == null)
            {
                return false;
            }
                   
            var moduleBaseAddress = IntPtr.Zero;

            // Find the injected dll base address
            
            foreach (var module in process.Modules.Cast<ProcessModule>())
            {
                if (module.ModuleName == Path.GetFileName(dllPath))
                {
                    moduleBaseAddress = module.BaseAddress;

                    break;
                }
            }
            
            if (moduleBaseAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Get the information about the header region of the module

            var memoryInformationSize = Marshal.SizeOf(typeof(MemoryBasicInformation));

            if (!VirtualQueryEx(processHandle, moduleBaseAddress, out var memoryInformation, memoryInformationSize))
            {
                return false;
            }

            // Generate a buffer to write over the header region with
            
            var buffer = new byte[(int) memoryInformation.RegionSize];

            // Write over the header region

            if (!WriteMemory(processHandle, moduleBaseAddress, buffer))
            {
                return false;
            }

            return true;
        }
    }
}