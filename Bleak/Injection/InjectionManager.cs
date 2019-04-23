using Bleak.Handlers;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Tools;
using System;
using System.IO;
using System.Linq;
using Bleak.Injection.Methods;

namespace Bleak.Injection
{
    internal class InjectionManager : IDisposable
    {
        private readonly InjectionProperties _injectionProperties;

        internal InjectionManager(int targetProcessId, byte[] dllBytes, bool manualMap, bool isExtension, bool randomiseDllName)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (targetProcessId <= 0 || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            if (manualMap)
            {
                _injectionProperties = new InjectionProperties(targetProcessId, dllBytes);
            }

            else if (randomiseDllName && isExtension)
            {
                // Assume the DLL is the newest file in the directory

                var directoryInfo = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "Bleak"));

                var newestFile = directoryInfo.GetFiles().OrderByDescending(file => file.LastWriteTime).First();

                _injectionProperties = new InjectionProperties(targetProcessId, newestFile.FullName);
            }

            else
            {
                // Create a temporary DLL on disk

                var temporaryDllName = randomiseDllName ? DllTools.GenerateRandomDllName() : DllTools.GenerateDllName(dllBytes);

                _injectionProperties = new InjectionProperties(targetProcessId, DllTools.CreateTemporaryDll(temporaryDllName, dllBytes));
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionProperties);
        }

        internal InjectionManager(int targetProcessId, string dllPath, bool isExtension, bool randomiseDllName)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (targetProcessId <= 0 || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            // Ensure a valid DLL exists at the provided path

            if (!File.Exists(dllPath) || Path.GetExtension(dllPath) != ".dll")
            {
                throw new ArgumentException("No DLL file exists at the provided path");
            }

            if (randomiseDllName && isExtension)
            {
                // Assume the DLL is the newest file in the directory

                var directoryInfo = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "Bleak"));

                var newestFile = directoryInfo.GetFiles().OrderByDescending(file => file.LastWriteTime).First();

                _injectionProperties = new InjectionProperties(targetProcessId, newestFile.FullName);
            }

            else if (randomiseDllName)
            {
                // Create a temporary DLL on disk

                var temporaryDllPath = DllTools.CreateTemporaryDll(DllTools.GenerateRandomDllName(), File.ReadAllBytes(dllPath));

                _injectionProperties = new InjectionProperties(targetProcessId, temporaryDllPath);
            }

            else
            {
                _injectionProperties = new InjectionProperties(targetProcessId, dllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionProperties);
        }

        internal InjectionManager(string targetProcessName, byte[] dllBytes, bool manualMap, bool isExtension, bool randomiseDllName)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(targetProcessName) || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            if (manualMap)
            {
                _injectionProperties = new InjectionProperties(targetProcessName, dllBytes);
            }

            else if (randomiseDllName && isExtension)
            {
                // Assume the DLL is the newest file in the directory

                var directoryInfo = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "Bleak"));

                var newestFile = directoryInfo.GetFiles().OrderByDescending(file => file.LastWriteTime).First();

                _injectionProperties = new InjectionProperties(targetProcessName, newestFile.FullName);
            }

            else
            {
                // Create a temporary DLL on disk

                var temporaryDllName = randomiseDllName ? DllTools.GenerateRandomDllName() : DllTools.GenerateDllName(dllBytes);

                _injectionProperties = new InjectionProperties(targetProcessName, DllTools.CreateTemporaryDll(temporaryDllName, dllBytes));
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionProperties);
        }

        internal InjectionManager(string targetProcessName, string dllPath, bool isExtension, bool randomiseDllName)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(targetProcessName) || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            // Ensure a valid DLL exists at the provided path

            if (!File.Exists(dllPath) || Path.GetExtension(dllPath) != ".dll")
            {
                throw new ArgumentException("No DLL file exists at the provided path");
            }

            if (randomiseDllName && isExtension)
            {
                // Assume the DLL is the newest file in the directory

                var directoryInfo = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "Bleak"));

                var newestFile = directoryInfo.GetFiles().OrderByDescending(file => file.LastWriteTime).First();

                _injectionProperties = new InjectionProperties(targetProcessName, newestFile.FullName);
            }

            else if (randomiseDllName)
            {
                // Create a temporary DLL on disk

                var temporaryDllPath = DllTools.CreateTemporaryDll(DllTools.GenerateRandomDllName(), File.ReadAllBytes(dllPath));

                _injectionProperties = new InjectionProperties(targetProcessName, temporaryDllPath);
            }

            else
            {
                _injectionProperties = new InjectionProperties(targetProcessName, dllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionProperties);
        }

        public void Dispose()
        {
            _injectionProperties.Dispose();
        }

        internal bool CallInjectionExtension<TExtension>() where TExtension : IInjectionExtension, new()
        {
            return new TExtension().Call(_injectionProperties);
        }

        internal bool CallInjectionMethod<TMethod>() where TMethod : IInjectionMethod, new()
        {   
            if (typeof(TMethod) == typeof(RtlCreateUserThread) && Environment.OSVersion.Version.Major == 6)
            {
                switch (Environment.OSVersion.Version.Minor)
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
            }
            
            return new TMethod().Call(_injectionProperties);
        }
    }
}
