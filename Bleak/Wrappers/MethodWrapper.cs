using Bleak.Handlers;
using Bleak.Tools;
using System;
using System.IO;

namespace Bleak.Wrappers
{
    internal class MethodWrapper : IDisposable
    {
        private readonly PropertyWrapper _propertyWrapper;

        internal MethodWrapper(int targetProcessId, byte[] dllBytes, bool randomiseDllName, bool methodIsManualMap)
        {
            // Ensure the users operating system is supported

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (targetProcessId <= 0 || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            if (methodIsManualMap)
            {
                _propertyWrapper = new PropertyWrapper(targetProcessId, dllBytes);
            }

            else
            {
                // Create a temporary DLL on disk

                var temporaryDllName = randomiseDllName ? WrapperTools.GenerateRandomDllName() : WrapperTools.GenerateDllName(dllBytes);

                var temporaryDllPath = WrapperTools.CreateTemporaryDll(temporaryDllName, dllBytes);

                _propertyWrapper = new PropertyWrapper(targetProcessId, temporaryDllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_propertyWrapper);
        }

        internal MethodWrapper(string targetProcessName, byte[] dllBytes, bool randomiseDllName, bool methodIsManualMap)
        {
            // Ensure the users operating system is supported

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(targetProcessName) || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            if (methodIsManualMap)
            {
                _propertyWrapper = new PropertyWrapper(targetProcessName, dllBytes);
            }

            else
            {
                // Create a temporary DLL on disk

                var temporaryDllName = randomiseDllName ? WrapperTools.GenerateRandomDllName() : WrapperTools.GenerateDllName(dllBytes);

                var temporaryDllPath = WrapperTools.CreateTemporaryDll(temporaryDllName, dllBytes);

                _propertyWrapper = new PropertyWrapper(targetProcessName, temporaryDllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_propertyWrapper);
        }

        internal MethodWrapper(int targetProcessId, string dllPath, bool randomiseDllName, bool methodIsManualMap)
        {
            // Ensure the users operating system is supported

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (targetProcessId <= 0 || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            if (randomiseDllName)
            {
                // Create a temporary DLL on disk

                var temporaryDllName = WrapperTools.GenerateRandomDllName();

                var temporaryDllPath = WrapperTools.CreateTemporaryDll(temporaryDllName, File.ReadAllBytes(dllPath));

                _propertyWrapper = methodIsManualMap ? new PropertyWrapper(targetProcessId, File.ReadAllBytes(temporaryDllPath)) : new PropertyWrapper(targetProcessId, temporaryDllPath);

            }

            else
            {
                _propertyWrapper = methodIsManualMap ? new PropertyWrapper(targetProcessId, File.ReadAllBytes(dllPath)) : new PropertyWrapper(targetProcessId, dllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_propertyWrapper);
        }

        internal MethodWrapper(string targetProcessName, string dllPath, bool randomiseDllName, bool methodIsManualMap)
        {
            // Ensure the users operating system is supported

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(targetProcessName) || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            if (randomiseDllName)
            {
                // Create a temporary DLL on disk

                var temporaryDllName = WrapperTools.GenerateRandomDllName();

                var temporaryDllPath = WrapperTools.CreateTemporaryDll(temporaryDllName, File.ReadAllBytes(dllPath));

                _propertyWrapper = methodIsManualMap ? new PropertyWrapper(targetProcessName, File.ReadAllBytes(temporaryDllPath)) : new PropertyWrapper(targetProcessName, temporaryDllPath);

            }

            else
            {
                _propertyWrapper = methodIsManualMap ? new PropertyWrapper(targetProcessName, File.ReadAllBytes(dllPath)) : new PropertyWrapper(targetProcessName, dllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_propertyWrapper);
        }

        public void Dispose()
        {
            _propertyWrapper.Dispose();
        }

        internal bool CreateRemoteThread()
        {
            return new Methods.CreateRemoteThread(_propertyWrapper).Call();
        }

        internal bool ManualMap()
        {
            return new Methods.ManualMap(_propertyWrapper).Call();
        }

        internal bool QueueUserApc()
        {
            return new Methods.QueueUserApc(_propertyWrapper).Call();
        }

        internal bool RtlCreateUserThread()
        {
            switch (Environment.OSVersion.Version.Major)
            {
                case 5:
                {
                    throw new PlatformNotSupportedException("RtlCreateUserThread is not supported on Windows XP");
                }
                
                case 6:
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
                    
                    break;
                }
            }

            return new Methods.RtlCreateUserThread(_propertyWrapper).Call();
        }

        internal bool SetThreadContext()
        {
            if (Environment.OSVersion.Version.Major == 5)
            {
                throw new PlatformNotSupportedException("SetThreadContext is not supported on Windows XP");
            }

            return new Methods.SetThreadContext(_propertyWrapper).Call();
        }
    }
}
