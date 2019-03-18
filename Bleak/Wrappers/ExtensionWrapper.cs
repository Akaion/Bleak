using Bleak.Handlers;
using Bleak.Tools;
using System;

namespace Bleak.Wrappers
{
    internal class ExtensionWrapper : IDisposable
    {
        private readonly PropertyWrapper PropertyWrapper;

        internal ExtensionWrapper(string targetProcessName, byte[] dllBytes)
        {
            // Ensure the users operating system is supported

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(targetProcessName) || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            // Generate a name for a temporary DLL

            var temporaryDllName =  WrapperTools.GenerateDllName(dllBytes);

            // Create a temporary DLL on disk

            var temporaryDllPath = WrapperTools.CreateTemporaryDll(temporaryDllName, dllBytes);

            PropertyWrapper = new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessName), temporaryDllPath);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(PropertyWrapper);
        }

        internal ExtensionWrapper(int targetProcessId, byte[] dllBytes)
        {
            // Ensure the users operating system is supported

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (targetProcessId <= 0 || dllBytes is null || dllBytes.Length == 0)
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            // Generate a name for a temporary DLL

            var temporaryDllName = WrapperTools.GenerateDllName(dllBytes);

            // Create a temporary DLL on disk

            var temporaryDllPath = WrapperTools.CreateTemporaryDll(temporaryDllName, dllBytes);

            PropertyWrapper = new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessId), temporaryDllPath);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(PropertyWrapper);
        }

        internal ExtensionWrapper(string targetProcessName, string dllPath)
        {
            // Ensure the users operating system is supported

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (string.IsNullOrWhiteSpace(targetProcessName) || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            PropertyWrapper = new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessName), dllPath);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(PropertyWrapper);
        }

        internal ExtensionWrapper(int targetProcessId, string dllPath)
        {
            // Ensure the users operating system is supported

            ValidationHandler.ValidateOperatingSystem();

            // Ensure the arguments passed in are valid

            if (targetProcessId <= 0 || string.IsNullOrWhiteSpace(dllPath))
            {
                throw new ArgumentException("One or more of the arguments provided were invalid");
            }

            PropertyWrapper = new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessId), dllPath);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(PropertyWrapper);
        }

        public void Dispose()
        {
            PropertyWrapper.Dispose();
        }

        internal bool EjectDll()
        {
            return new Extensions.EjectDll(PropertyWrapper).Call();
        }

        internal bool EraseHeaders()
        {
            return new Extensions.EraseHeaders(PropertyWrapper).Call();
        }

        internal bool RandomiseHeaders()
        {
            return new Extensions.RandomiseHeaders(PropertyWrapper).Call();
        }

        internal bool UnlinkFromPeb()
        {
            return new Extensions.UnlinkFromPeb(PropertyWrapper).Call();
        }
    }
}
