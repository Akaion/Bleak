using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static Simple_Injection.Etc.Native;
using static Simple_Injection.Etc.Wrapper;

namespace Simple_Injection.Extensions
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

            var moduleBaseAddress = IntPtr.Zero;

            // Find the dll base address

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

            // Get the information about the header region of the dll

            var memoryInformationSize = Marshal.SizeOf(typeof(MemoryBasicInformation));

            if (!VirtualQueryEx(processHandle, moduleBaseAddress, out var memoryInformation, memoryInformationSize))
            {
                return false;
            }

            // Generate a buffer to write over the header region with

            var buffer = new byte[(int)memoryInformation.RegionSize];

            // Fill the buffer with random bytes

            new Random().NextBytes(buffer);

            // Write over the header region

            return WriteMemory(processHandle, moduleBaseAddress, buffer);
        }
    }
}
