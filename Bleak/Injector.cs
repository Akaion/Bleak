using System;
using System.IO;
using Bleak.Handlers;
using Bleak.Injection;
using Bleak.Tools;

namespace Bleak
{
    public class Injector : IDisposable
    {
        private readonly InjectionManager _injectionManager;

        public Injector(InjectionMethod injectionMethod, int processId, byte[] dllBytes)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (processId <= 0 || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            _injectionManager = injectionMethod == InjectionMethod.ManualMap
                              ? new InjectionManager(injectionMethod, processId, dllBytes)
                              : new InjectionManager(injectionMethod, processId, DllTools.CreateTemporaryDll(dllBytes));
        }

        public Injector(InjectionMethod injectionMethod, int processId, string dllPath, bool randomiseDllName = false)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (processId <= 0 || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            // Ensure a valid DLL exists at the provided path

            if (!File.Exists(dllPath) || Path.GetExtension(dllPath) != ".dll")
            {
                throw new ArgumentException("No DLL exists at the provided path");
            }

            if (randomiseDllName)
            {
                // Create a temporary DLL on disk

                var temporaryDllPath = DllTools.CreateTemporaryDll(File.ReadAllBytes(dllPath));

                _injectionManager = new InjectionManager(injectionMethod, processId, temporaryDllPath);
            }

            else
            {
                _injectionManager = new InjectionManager(injectionMethod, processId, dllPath);
            }
        }

        public Injector(InjectionMethod injectionMethod, string processName, byte[] dllBytes)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(processName) || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            _injectionManager = injectionMethod == InjectionMethod.ManualMap
                              ? new InjectionManager(injectionMethod, processName, dllBytes)
                              : new InjectionManager(injectionMethod, processName, DllTools.CreateTemporaryDll(dllBytes));
        }

        public Injector(InjectionMethod injectionMethod, string processName, string dllPath, bool randomiseDllName = false)
        {
            // Ensure the users operating system is valid

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(processName) || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            // Ensure a valid DLL exists at the provided path

            if (!File.Exists(dllPath) || Path.GetExtension(dllPath) != ".dll")
            {
                throw new ArgumentException("No DLL exists at the provided path");
            }

            if (randomiseDllName)
            {
                // Create a temporary DLL on disk

                var temporaryDllPath = DllTools.CreateTemporaryDll(File.ReadAllBytes(dllPath));

                _injectionManager = new InjectionManager(injectionMethod, processName, temporaryDllPath);
            }

            else
            {
                _injectionManager = new InjectionManager(injectionMethod, processName, dllPath);
            }
        }

        public void Dispose()
        {
            _injectionManager.Dispose();
        }

        public bool EjectDll()
        {
            return _injectionManager.EjectDll();
        }

        public bool HideDllFromPeb()
        {
            return _injectionManager.HideDllFromPeb();
        }

        public IntPtr InjectDll()
        {
            return _injectionManager.InjectDll();
        }

        public bool RandomiseDllHeaders()
        {
            return _injectionManager.RandomiseDllHeaders();
        }
    }
}