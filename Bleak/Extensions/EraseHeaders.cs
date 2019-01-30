using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Bleak.Etc;
using Bleak.Services;

namespace Bleak.Extensions
{
    internal class EraseHeaders : IDisposable
    {
        private readonly Properties _properties;
        
        internal EraseHeaders(Process process, string dllPath)
        {
            _properties = new Properties(process, dllPath);
        }
        
        public void Dispose()
        {
            _properties?.Dispose();
        }
        
        internal bool Erase()
        {
            // Get the name of the dll
            
            var dllName = Path.GetFileName(_properties.DllPath);
            
            // Get an instance of the dll in the process

            var module = Tools.GetProcessModules(_properties.ProcessId).SingleOrDefault(m => string.Equals(m.Module, dllName, StringComparison.OrdinalIgnoreCase));
            
            if (module.Equals(default(Native.ModuleEntry)))
            {
                throw new ArgumentException($"There is no module named {dllName} loaded in the process");
            }
            
            // Get the base address of the dll
            
            var dllBaseAddress = module.BaseAddress;
            
            // Get the information about the header region of the dll
            
            var memoryInformationSize = Marshal.SizeOf(typeof(Native.MemoryBasicInformation));
            
            if (!Native.VirtualQueryEx(_properties.ProcessHandle, dllBaseAddress, out var memoryInformation, memoryInformationSize))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to query the memory of the process");
            }
            
            // Create a buffer to write over the header region with
            
            var buffer = new byte[(int) memoryInformation.RegionSize];
            
            // Write over the header region with the buffer
            
            try
            {
                _properties.MemoryModule.WriteMemory(_properties.ProcessId, dllBaseAddress, buffer);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write over the header region");
            }
            
            return true;
        }
    }
}