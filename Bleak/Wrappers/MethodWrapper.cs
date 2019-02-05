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
            // Ensure the operating system is Windows

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
            // Ensure the operating system is Windows

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
            // Ensure the operating system is Windows

            ValidateOperatingSystem.Validate();
            
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
            // Ensure the operating system is Windows

            ValidateOperatingSystem.Validate();
            
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
            using (var injectionMethod = new CreateRemoteThread(_process, _dllPath))
            {
                // Inject the dll
            
                return injectionMethod.Inject();
            }  
        }
        
        internal bool ManualMap()
        {
            // Ensure the operating system supports ManualMap
            
            var osVersion = Environment.Version;

            if (osVersion.Major == 5)
            {
                throw new PlatformNotSupportedException("ManualMap is not supported on Windows XP");
            }
            
            using (var injectionMethod = new ManualMap(_process, _dllPath))
            {
                // Inject the dll
            
                return injectionMethod.Inject();
            }
        }
        
        internal bool NtCreateThreadEx()
        {
            // Ensure the operating system supports NtCreateThreadEx
            
            var osVersion = Environment.Version;

            if (osVersion.Major == 5)
            {
                throw new PlatformNotSupportedException("NtCreateThreadEx is not supported on Windows XP");
            }
            
            using (var injectionMethod = new NtCreateThreadEx(_process, _dllPath))
            {
                // Inject the dll
            
                return injectionMethod.Inject();
            }
        }
        
        internal bool QueueUserApc()
        {
            using (var injectionMethod = new QueueUserApc(_process, _dllPath))
            {
                // Inject the dll
            
                return injectionMethod.Inject();
            }
        }
        
        internal bool RtlCreateUserThread()
        {
            // Ensure the operating system supports RtlCreateUserThread
            
            var osVersion = Environment.Version;
            
            switch (osVersion.Major)
            {
                case 5:
                {
                    throw new PlatformNotSupportedException("RtlCreateUserThread is not supported on Windows XP");
                }

                case 6:
                {
                    switch (osVersion.Minor)
                    {
                        case 0:
                        {
                            throw new PlatformNotSupportedException("RtlCreateUserThread is not supported on Windows Vista");
                        }

                        case 1:
                        {
                            throw new PlatformNotSupportedException("RtlCreateUserThread is not supported on Windows 7");
                        }
                    }

                    break;
                }
            }
            
            using (var injectionMethod = new RtlCreateUserThread(_process, _dllPath))
            {
                // Inject the dll
            
                return injectionMethod.Inject();
            }
        }
        
        internal bool SetThreadContext()
        {
            // Ensure the operating system supports SetThreadContext
            
            var osVersion = Environment.Version;

            if (osVersion.Major == 5)
            {
                throw new PlatformNotSupportedException("SetThreadContext is not supported on Windows XP");
            }
            
            using (var injectionMethod = new SetThreadContext(_process, _dllPath))
            {
                // Inject the dll
            
                return injectionMethod.Inject();
            }
        }
        
        internal bool ZwCreateThreadEx()
        {
            // Ensure the operating system supports ZwCreateThreadEx
            
            var osVersion = Environment.Version;

            if (osVersion.Major == 5)
            {
                throw new PlatformNotSupportedException("ZwCreateThreadEx is not supported on Windows XP");
            }
            
            using (var injectionMethod = new ZwCreateThreadEx(_process, _dllPath))
            {
                // Inject the dll
            
                return injectionMethod.Inject();
            }
        }
    }
}