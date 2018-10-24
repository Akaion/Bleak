using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static Simple_Injection.Etc.Native;

namespace Simple_Injection.Extensions
{
    public static class MEraseHeaders
    {
        public static bool Erase(string dllPath, string processName)
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
            
            // Get the handle of the specified process

            var processHandle = process.Handle;

            if (processHandle == IntPtr.Zero)
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
                }
            }
            
            if (moduleBaseAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Get the information about the header region of the module

            var memoryInformationSize = Marshal.SizeOf(typeof(MemoryInformation));

            if (!VirtualQueryEx(processHandle, moduleBaseAddress, out var memoryInformation, (uint) memoryInformationSize))
            {
                return false;
            }

            // Generate a buffer to write over the header region with
            
            var buffer = new byte[(uint) memoryInformation.RegionSize];

            // Change the protection of the header region

            if (!VirtualProtectEx(processHandle, moduleBaseAddress, (uint) buffer.Length, 0x40, out var oldProtection))
            {
                return false;
            }
            
            // Write over the header region

            if (!WriteProcessMemory(processHandle, moduleBaseAddress, buffer, (uint) buffer.Length, 0))
            {
                return false;
            }
            
            // Restore the protection of the header region

            if (!VirtualProtectEx(processHandle, moduleBaseAddress, (uint) buffer.Length, oldProtection, out oldProtection))
            {
                return false;
            }

            return true;
        }
    }
}