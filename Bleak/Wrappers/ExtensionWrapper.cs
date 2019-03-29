using Bleak.Handlers;
using Bleak.Tools;
using System;
using System.IO;
using System.Linq;

namespace Bleak.Wrappers
{
    internal class ExtensionWrapper : IDisposable
    {
        private readonly PropertyWrapper _propertyWrapper;

        internal ExtensionWrapper(int targetProcessId, byte[] dllBytes, bool randomiseDllName)
        {
            // Ensure the users operating system is supported

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (targetProcessId <= 0 || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            if (randomiseDllName)
            {
                // Assume the DLL is the newest file in the temporary directory

                var temporaryDirectoryInfo = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "Bleak"));

                var newestTemporaryFile = temporaryDirectoryInfo.GetFiles().OrderByDescending(file => file.LastWriteTime).First();

                _propertyWrapper = new PropertyWrapper(targetProcessId, newestTemporaryFile.FullName);
            }

            else
            {
                // Get the file path of the DLL on disk

                var temporaryDirectory = Path.Combine(Path.GetTempPath(), "Bleak");

                var temporaryDllName = WrapperTools.GenerateDllName(dllBytes);

                var temporaryDllPath = Path.Combine(temporaryDirectory, temporaryDllName);

                _propertyWrapper = new PropertyWrapper(targetProcessId, temporaryDllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_propertyWrapper);
        }

        internal ExtensionWrapper(string targetProcessName, byte[] dllBytes, bool randomiseDllName)
        {
            // Ensure the users operating system is supported

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(targetProcessName) || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            if (randomiseDllName)
            {
                // Assume the DLL is the newest file in the temporary directory

                var temporaryDirectoryInfo = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "Bleak"));

                var newestTemporaryFile = temporaryDirectoryInfo.GetFiles().OrderByDescending(file => file.LastWriteTime).First();

                _propertyWrapper = new PropertyWrapper(targetProcessName, newestTemporaryFile.FullName);
            }

            else
            {
                // Get the file path of the DLL on disk

                var temporaryDirectory = Path.Combine(Path.GetTempPath(), "Bleak");

                var temporaryDllName = WrapperTools.GenerateDllName(dllBytes);

                var temporaryDllPath = Path.Combine(temporaryDirectory, temporaryDllName);

                _propertyWrapper = new PropertyWrapper(targetProcessName, temporaryDllPath);
            }

            ValidationHandler.ValidateDllArchitecture(_propertyWrapper);

        }

        internal ExtensionWrapper(int targetProcessId, string dllPath, bool randomiseDllName)
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
                // Assume the DLL is the newest file in the temporary directory

                var temporaryDirectoryInfo = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "Bleak"));

                var newestTemporaryFile = temporaryDirectoryInfo.GetFiles().OrderByDescending(file => file.LastWriteTime).First();

                _propertyWrapper = new PropertyWrapper(targetProcessId, newestTemporaryFile.FullName);
            }

            else
            {
                _propertyWrapper = new PropertyWrapper(targetProcessId, dllPath);
            }

            ValidationHandler.ValidateDllArchitecture(_propertyWrapper);
        }

        internal ExtensionWrapper(string targetProcessName, string dllPath, bool randomiseDllName)
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
                // Assume the DLL is the newest file in the temporary directory

                var temporaryDirectoryInfo = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "Bleak"));

                var newestTemporaryFile = temporaryDirectoryInfo.GetFiles().OrderByDescending(file => file.LastWriteTime).First();

                _propertyWrapper = new PropertyWrapper(targetProcessName, newestTemporaryFile.FullName);
            }

            else
            {
                _propertyWrapper = new PropertyWrapper(targetProcessName, dllPath);
            }

            ValidationHandler.ValidateDllArchitecture(_propertyWrapper);
        }

        public void Dispose()
        {
            _propertyWrapper.Dispose();
        }

        internal bool EjectDll()
        {
            return new Extensions.EjectDll(_propertyWrapper).Call();
        }

        internal bool EraseDllHeaders()
        {
            return new Extensions.EraseDllHeaders(_propertyWrapper).Call();
        }

        internal bool RandomiseDllHeaders()
        {
            return new Extensions.RandomiseDllHeaders(_propertyWrapper).Call();
        }

        internal bool UnlinkDllFromPeb()
        {
            return new Extensions.UnlinkDllFromPeb(_propertyWrapper).Call();
        }
    }
}
