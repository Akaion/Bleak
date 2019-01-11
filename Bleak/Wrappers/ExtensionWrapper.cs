using System;
using System.Diagnostics;
using System.IO;
using Bleak.Extensions;
using Bleak.Services;

namespace Bleak.Wrappers
{
    internal class ExtensionWrapper
    {
        private readonly Process _process;

        private readonly string _dllPath;

        internal ExtensionWrapper(string processName, string dllPath)
        {
            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided was invalid");
            }
            
            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                throw new FileNotFoundException("No file exists at the provided location");
            }
            
            // Get an instance of the process

            Process process;
            
            try
            {
                process = Process.GetProcessesByName(processName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                // The process isn't currently running
                
                throw new ArgumentException($"No process with name {processName} is currently running");
            }
            
            // Ensure the process architecture matches the dll architecture
            
            ValidateArchitecture.Validate(process, dllPath);
            
            // Store the values

            _process = process;

            _dllPath = dllPath;
        }

        internal ExtensionWrapper(int processId, string dllPath)
        {
            // Ensure the arguments passed in are valid

            if (processId <= 0|| string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided was invalid");
            }
            
            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                throw new FileNotFoundException("No file exists at the provided location");
            }
            
            // Get an instance of the process

            Process process;
            
            try
            {
                process = Process.GetProcessById(processId);
            }

            catch (ArgumentException)
            {
                // The process isn't currently running
                
                throw new ArgumentException($"No process with id {processId} is currently running");
            }
            
            // Ensure the process architecture matches the dll architecture
            
            ValidateArchitecture.Validate(process, dllPath);
            
            // Store the values

            _process = process;

            _dllPath = dllPath;
        }

        internal bool EjectDll()
        {
            var extensionMethod = new EjectDll();
            
            // Eject the dll

            return extensionMethod.Eject(_process, _dllPath);
        }

        internal bool EraseHeaders()
        {
            var extensionMethod = new EraseHeaders();
            
            // Erase the dll headers

            return extensionMethod.Erase(_process, _dllPath);
        }

        internal bool RandomiseHeaders()
        {
            var extensionMethod = new RandomiseHeaders();
            
            // Randomise the dll headers

            return extensionMethod.Randomise(_process, _dllPath);
        }

        internal bool UnlinkFromPeb()
        {
            var extensionMethod = new UnlinkFromPeb();
            
            // Unlink the dll from the peb

            return extensionMethod.Unlink(_process, _dllPath);
        }
    }
}