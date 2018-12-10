using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using PeNet;
using static Bleak.Etc.Native;
using static Bleak.Etc.Wrapper;

namespace Bleak.Extensions
{
    internal static class RandomiseHeaders
    {
        internal static bool Randomise(string dllPath, string processName)
        {
            // Ensure both parameters are valid

            if (string.IsNullOrEmpty(dllPath) || string.IsNullOrEmpty(processName))
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
                process = Process.GetProcessesByName(processName).FirstOrDefault();
            }

            catch (IndexOutOfRangeException)
            {
                return false;
            }

            // Randomise the headers

            return Randomise(dllPath, process);
        }

        internal static bool Randomise(string dllPath, int processId)
        {
            // Ensure both parameters are valid

            if (string.IsNullOrEmpty(dllPath) || processId == 0)
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

            // Randomise the headers

            return Randomise(dllPath, process);
        }

        private static bool Randomise(string dllPath, Process process)
        {
            // Get the handle of the specified process

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

            // Get the information about the header region of the dll

            var memoryInformationSize = Marshal.SizeOf(typeof(MemoryBasicInformation));

            if (!VirtualQueryEx(processHandle, dllBaseAddress, out var memoryInformation, memoryInformationSize))
            {
                return false;
            }

            // Generate a buffer to write over the header region with

            var buffer = new byte[(int) memoryInformation.RegionSize];

            // Fill the buffer with random bytes

            new Random().NextBytes(buffer);

            // Write over the header region

            return WriteMemory(processHandle, dllBaseAddress, buffer);
        }
    }
}