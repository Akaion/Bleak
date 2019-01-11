using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Bleak.Etc;
using Bleak.Services;
using Jupiter;

namespace Bleak.Extensions
{
    internal class EraseHeaders
    {
        private readonly MemoryModule _memoryModule;
        
        internal EraseHeaders()
        {
            _memoryModule = new MemoryModule();
        }
        
        internal bool Erase(Process process, string dllPath)
        {
            // Get the id of the process

            var processId = process.Id;
            
            // Get the name of the dll

            var dllName = Path.GetFileName(dllPath);
            
            // Get an instance of the dll in the process
            
            var module = process.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, dllName, StringComparison.OrdinalIgnoreCase));

            if (module is null)
            {
                throw new ArgumentException($"There is no module named {dllName} loaded in the process");
            }
            
            // Get the base address of the dll

            var dllBaseAddress = module.BaseAddress;

            // Open a handle to the process

            var processHandle = process.SafeHandle;
            
            // Get the information about the header region of the dll

            var memoryInformationSize = Marshal.SizeOf(typeof(Native.MemoryBasicInformation));

            if (!Native.VirtualQueryEx(processHandle, dllBaseAddress, out var memoryInformation, memoryInformationSize))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to query the memory of the process");
            }
            
            // Create a buffer to write over the header region with

            var buffer = new byte[(int) memoryInformation.RegionSize];

            // Write over the header region with the buffer

            try
            {
                _memoryModule.WriteMemory(processId, dllBaseAddress, buffer);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write over the header region");
            }

            // Close the handle opened to the process
            
            processHandle?.Close();
            
            return true;
        }
    }
}