using Bleak.Handlers;
using Bleak.Tools;
using System;
using System.IO;

namespace Bleak.Wrappers
{
    internal class MethodWrapper : IDisposable
    {
        private readonly PropertyWrapper PropertyWrapper;

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
                PropertyWrapper = new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessName), dllBytes);
            }

            else
            {
                // Generate a name for a temporary DLL

                var temporaryDllName = randomiseDllName ? WrapperTools.GenerateRandomDllName() : WrapperTools.GenerateDllName(dllBytes);

                // Create a temporary DLL on disk

                var temporaryDllPath = WrapperTools.CreateTemporaryDll(temporaryDllName, dllBytes);

                PropertyWrapper = new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessName), temporaryDllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(PropertyWrapper);
        }

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
                PropertyWrapper = new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessId), dllBytes);
            }

            else
            {
                // Generate a name for a temporary DLL

                var temporaryDllName = randomiseDllName ? WrapperTools.GenerateRandomDllName() : WrapperTools.GenerateDllName(dllBytes);

                // Create a temporary DLL on disk

                var temporaryDllPath = WrapperTools.CreateTemporaryDll(temporaryDllName, dllBytes);

                PropertyWrapper = new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessId), temporaryDllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(PropertyWrapper);
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
                // Generate a name for a temporary DLL

                var temporaryDllName = WrapperTools.GenerateRandomDllName();

                // Create a temporary DLL on disk

                var temporaryDllPath = WrapperTools.CreateTemporaryDll(temporaryDllName, File.ReadAllBytes(dllPath));

                PropertyWrapper = methodIsManualMap ? new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessName), File.ReadAllBytes(temporaryDllPath)) : new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessName), temporaryDllPath);
            }

            else
            {
                PropertyWrapper = methodIsManualMap ? new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessName), File.ReadAllBytes(dllPath)) : new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessName), dllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(PropertyWrapper);
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
                // Generate a name for a temporary DLL

                var temporaryDllName = WrapperTools.GenerateRandomDllName();

                // Create a temporary DLL on disk

                var temporaryDllPath = WrapperTools.CreateTemporaryDll(temporaryDllName, File.ReadAllBytes(dllPath));

                PropertyWrapper = methodIsManualMap ? new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessId), File.ReadAllBytes(temporaryDllPath)) : new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessId), temporaryDllPath);
            }

            else
            {
                PropertyWrapper = methodIsManualMap ? new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessId), File.ReadAllBytes(dllPath)) : new PropertyWrapper(WrapperTools.GetTargetProcess(targetProcessId), dllPath);
            }

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(PropertyWrapper);
        }

        public void Dispose()
        {
            PropertyWrapper.Dispose();
        }

        internal bool CreateRemoteThread()
        {
            return new Methods.CreateRemoteThread(PropertyWrapper).Call();
        }

        internal bool NtCreateThreadEx()
        {
            return new Methods.NtCreateThreadEx(PropertyWrapper).Call();
        }

        internal bool ManualMap()
        {
            return new Methods.ManualMap(PropertyWrapper).Call();
        }

        internal bool QueueUserApc()
        {
            return new Methods.QueueUserApc(PropertyWrapper).Call();
        }

        internal bool RtlCreateUserThread()
        {
            return new Methods.RtlCreateUserThread(PropertyWrapper).Call();
        }

        internal bool SetThreadContext()
        {
            return new Methods.SetThreadContext(PropertyWrapper).Call();
        }
    }
}
