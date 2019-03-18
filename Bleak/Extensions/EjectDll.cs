using Bleak.Extensions.Interfaces;
using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Tools;
using Bleak.Wrappers;
using System;
using System.IO;
using System.Linq;

namespace Bleak.Extensions
{
    internal class EjectDll : IExtensionMethod
    {
        private readonly PropertyWrapper PropertyWrapper;

        internal EjectDll(PropertyWrapper propertyWrapper)
        {
            PropertyWrapper = propertyWrapper;
        }

        public bool Call()
        {
            // Get the address of the FreeLibraryAndExitThread function in the target process

            var freeLibraryAndExitThreadAddress = NativeTools.GetFunctionAddress(PropertyWrapper, "kernel32.dll", "FreeLibraryAndExitThread");

            var dllName = Path.GetFileName(PropertyWrapper.DllPath);

            // Get an instance of the DLL in the target process

            var module = NativeTools.GetProcessModules(PropertyWrapper.Process.Id).FirstOrDefault(m => m.Module.Equals(dllName, StringComparison.OrdinalIgnoreCase));

            if (module.Equals(default))
            {
                throw new ArgumentException($"Failed to find {dllName} in the target processes module list");
            }

            // Create a remote thread to call FreeLibraryAndExitThread in the target process

            var remoteThreadHandle = (SafeThreadHandle) PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtCreateThreadEx>(PropertyWrapper.ProcessHandle.Value, freeLibraryAndExitThreadAddress, module.BaseAddress);

            // Wait for the remote thread to finish its task

            PInvoke.WaitForSingleObject(remoteThreadHandle, uint.MaxValue);

            remoteThreadHandle.Dispose();

            return true;
        }
    }
}
