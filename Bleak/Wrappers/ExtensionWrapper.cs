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
            // Ensure the operating system is valid

            ValidateOperatingSystem.Validate();
            
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
            
            // Get an instance of the remote process
            
            Process process;
            
            try
            {
                process = Process.GetProcessesByName(processName)[0];
            }
            
            catch (IndexOutOfRangeException)
            {
                // The remote process isn't currently running
                
                throw new ArgumentException($"No process with name {processName} is currently running");
            }
            
            // Ensure the remote process architecture matches the dll architecture
            
            ValidateArchitecture.Validate(process, dllPath);
            
            // Store the values
            
            _process = process;
            
            _dllPath = dllPath;
        }
        
        internal ExtensionWrapper(int processId, string dllPath)
        {
            // Ensure the operating system is valid

            ValidateOperatingSystem.Validate();
            
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
            
            // Get an instance of the remote process
            
            Process process;
            
            try
            {
                process = Process.GetProcessById(processId);
            }
            
            catch (ArgumentException)
            {
                // The remote process isn't currently running
                
                throw new ArgumentException($"No process with id {processId} is currently running");
            }
            
            // Ensure the remote process architecture matches the dll architecture
            
            ValidateArchitecture.Validate(process, dllPath);
            
            // Store the values
            
            _process = process;
            
            _dllPath = dllPath;
        }
        
        internal ExtensionWrapper(string processName, byte[] dllBytes)
        {
            // Ensure the operating system is valid

            ValidateOperatingSystem.Validate();
            
            // Ensure the arguments passed in are valid
            
            if (string.IsNullOrWhiteSpace(processName) || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided was invalid");
            }
            
            // Convert the dll bytes to a temporary file on disk
            
            var temporaryDllPath = Path.Combine(Path.GetTempPath(), "Bleak.dll");
            
            if (File.Exists(temporaryDllPath))
            {
                File.Delete(temporaryDllPath);
                
                File.WriteAllBytes(temporaryDllPath, dllBytes);
            }
            
            else
            {
                File.WriteAllBytes(temporaryDllPath, dllBytes);
            }
            
            // Get an instance of the remote process
            
            Process process;
            
            try
            {
                process = Process.GetProcessesByName(processName)[0];
            }
            
            catch (IndexOutOfRangeException)
            {
                // The remote process isn't currently running
                
                throw new ArgumentException($"No process with name {processName} is currently running");
            }
            
            // Ensure the remote process architecture matches the dll architecture
            
            ValidateArchitecture.Validate(process, temporaryDllPath);
            
            // Store the values
            
            _process = process;
            
            _dllPath = temporaryDllPath;
        }
        
        internal ExtensionWrapper(int processId, byte[] dllBytes)
        {
            // Ensure the operating system is valid

            ValidateOperatingSystem.Validate();
            
            // Ensure the arguments passed in are valid
            
            if (processId <= 0 || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided was invalid");
            }
            
            // Convert the dll bytes to a temporary file on disk
            
            var temporaryDllPath = Path.Combine(Path.GetTempPath(), "Bleak.dll");
            
            if (File.Exists(temporaryDllPath))
            {
                File.Delete(temporaryDllPath);
                
                File.WriteAllBytes(temporaryDllPath, dllBytes);
            }
            
            else
            {
                File.WriteAllBytes(temporaryDllPath, dllBytes);
            }
            
            // Get an instance of the remote process
            
            Process process;
            
            try
            {
                process = Process.GetProcessById(processId);
            }
            
            catch (ArgumentException)
            {
                // The remote process isn't currently running
                
                throw new ArgumentException($"No process with id {processId} is currently running");
            }
            
            // Ensure the remote process architecture matches the dll architecture
            
            ValidateArchitecture.Validate(process, temporaryDllPath);
            
            // Store the values
            
            _process = process;
            
            _dllPath = temporaryDllPath;
        }
        
        internal bool EjectDll()
        {
            using (var extensionMethod = new EjectDll(_process, _dllPath))
            {
                // Eject the dll
            
                return extensionMethod.Eject();
            }
        }
        
        internal bool EraseHeaders()
        {
            using (var extensionMethod = new EraseHeaders(_process, _dllPath))
            {
                // Erase the dll headers
            
                return extensionMethod.Erase();
            }
        }
        
        internal bool RandomiseHeaders()
        {
            using (var extensionMethod = new RandomiseHeaders(_process, _dllPath))
            {
                // Randomise the dll headers
            
                return extensionMethod.Randomise();
            }
        }
        
        internal bool UnlinkFromPeb()
        {
            using (var extensionMethod = new UnlinkFromPeb(_process, _dllPath))
            {
                // Unlink the dll from the peb
            
                return extensionMethod.Unlink();
            }
        }
    }
}