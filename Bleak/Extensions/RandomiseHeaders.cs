using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Jupiter;
using static Bleak.Etc.Native;


namespace Bleak.Extensions
{
    internal class RandomiseHeaders
    {
        private readonly MemoryModule _memoryModule;
        
        internal RandomiseHeaders()
        {
            _memoryModule = new MemoryModule();
        }

        internal bool Randomise(Process process, string dllPath)
        {
            // Get the id of the process

            var processId = process.Id;
            
            // Get the name of the dll

            var dllName = Path.GetFileName(dllPath);
            
            // Get an instance of the dll in the process
            
            var module = process.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, dllName, StringComparison.OrdinalIgnoreCase));

            if (module is null)
            {
                return false;
            }
            
            // Get the base address of the dll

            var dllBaseAddress = module.BaseAddress;

            if (dllBaseAddress == IntPtr.Zero)
            {
                return false;
            }

            // Open a handle to the process

            var processHandle = process.SafeHandle;
            
            // Get the information about the header region of the dll

            var memoryInformationSize = Marshal.SizeOf(typeof(MemoryBasicInformation));

            if (!VirtualQueryEx(processHandle, dllBaseAddress, out var memoryInformation, memoryInformationSize))
            {
                return false;
            }
            
            // Create a buffer to write over the header region with

            var buffer = new byte[(int) memoryInformation.RegionSize];

            // Fill the buffer with random bytes

            new Random().NextBytes(buffer);
            
            // Write over the header region with the buffer
            
            return _memoryModule.WriteMemory(processId, dllBaseAddress, buffer);
        }  
    }
}