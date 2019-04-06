using Bleak.Native;
using Bleak.RemoteProcess.Objects;
using Bleak.SafeHandle;
using Bleak.Syscall.Definitions;
using Bleak.Wrappers;
using System;
using System.IO;

namespace Bleak.Extensions
{
    internal class EjectDll
    {
        private readonly PropertyWrapper _propertyWrapper;

        internal EjectDll(PropertyWrapper propertyWrapper)
        {
            _propertyWrapper = propertyWrapper;
        }

        internal bool Call()
        {
            // Get the address of the FreeLibraryAndExitThread function

            var freeLibraryAndExitThreadAddress = _propertyWrapper.TargetProcess.GetFunctionAddress("kernel32.dll", "FreeLibraryAndExitThread");

            var dllName = Path.GetFileName(_propertyWrapper.DllPath);

            // Look for the DLL in the module list of the target process

            var module = _propertyWrapper.TargetProcess.Modules.Find(m => m.Name == dllName);

            if (module.Equals(default(ModuleInstance)))
            {
                throw new ArgumentException($"No DLL with the name {dllName} was found in the target processes module list");
            }

            // Create a thread to call FreeLibraryAndExitThread in the target process

            var remoteThreadHandle = (SafeThreadHandle) _propertyWrapper.SyscallManager.InvokeSyscall<NtCreateThreadEx>(_propertyWrapper.TargetProcess.Handle, freeLibraryAndExitThreadAddress, module.BaseAddress);

            PInvoke.WaitForSingleObject(remoteThreadHandle, uint.MaxValue);

            remoteThreadHandle.Dispose();

            return true;
        }
    }
}
