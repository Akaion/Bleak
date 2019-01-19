using System;
using System.Diagnostics;
using System.IO;
using Bleak.Methods;
using Bleak.Services;

namespace Bleak.Wrappers
{
    internal class MethodWrapper
    {
        private readonly Process _process;

        private readonly string _dllPath;

        internal MethodWrapper(string processName, string dllPath)
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

        internal MethodWrapper(int processId, string dllPath)
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

        internal MethodWrapper(string processName, byte[] dllBytes)
        {
            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(processName) || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided was invalid");
            }
            
            // Convert the dll bytes to a temporary file on disk

            var temporaryDllPath = Path.Combine(Path.GetTempPath(), "Bleak.dll");
            
            if (!File.Exists(temporaryDllPath))
            {
                File.WriteAllBytes(temporaryDllPath, dllBytes);
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
            
            ValidateArchitecture.Validate(process, temporaryDllPath);
            
            // Store the values

            _process = process;

            _dllPath = temporaryDllPath;
        }

        internal MethodWrapper(int processId, byte[] dllBytes)
        {
            // Ensure the arguments passed in are valid

            if (processId <= 0 || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided was invalid");
            }
            
            // Convert the dll bytes to a temporary file on disk

            var temporaryDllPath = Path.Combine(Path.GetTempPath(), "Bleak.dll");
            
            if (!File.Exists(temporaryDllPath))
            {
                File.WriteAllBytes(temporaryDllPath, dllBytes);
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
            
            ValidateArchitecture.Validate(process, temporaryDllPath);
            
            // Store the values

            _process = process;

            _dllPath = temporaryDllPath;
        }
        
        internal bool CreateRemoteThread()
        {
            var injectionMethod = new CreateRemoteThread();
            
            // Inject the dll
            
            return injectionMethod.Inject(_process, _dllPath);
        }

        internal bool ManualMap()
        {
            var injectionMethod = new ManualMap();
            
            // Inject the dll
            
            return injectionMethod.Inject(_process, _dllPath);
        }

        internal bool NtCreateThreadEx()
        {
            var injectionMethod = new NtCreateThreadEx();
            
            // Inject the dll

            return injectionMethod.Inject(_process, _dllPath);
        }

        internal bool QueueUserApc()
        {
            var injectionMethod = new QueueUserApc();
            
            // Inject the dll

            return injectionMethod.Inject(_process, _dllPath);
        }

        internal bool RtlCreateUserThread()
        {
            var injectionMethod = new RtlCreateUserThread();
            
            // Inject the dll

            return injectionMethod.Inject(_process, _dllPath);
        }

        internal bool SetThreadContext()
        {
            var injectionMethod = new SetThreadContext();
            
            // Inject the dll
            
            return injectionMethod.Inject(_process, _dllPath);
        }

        internal bool ZwCreateThreadEx()
        {
            var injectionMethod = new ZwCreateThreadEx();

            // Inject the dll
            
            return injectionMethod.Inject(_process, _dllPath);
        }
    }
}