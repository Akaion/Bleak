using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native;
using Bleak.Native.SafeHandle;
using Bleak.RemoteProcess.Objects;
using Bleak.Syscall.Definitions;
using System;
using System.IO;

namespace Bleak.Injection.Extensions
{
    internal class EjectDll : IInjectionExtension
    {
        public bool Call(InjectionProperties injectionProperties)
        {
            // Get the address of FreeLibraryAndExitThread function in the target process

            var freeLibraryAndExitThreadAddress = injectionProperties.RemoteProcess.GetFunctionAddress("kernel32.dll", "FreeLibraryAndExitThread");

            // Look for the DLL in the module list of the target process

            var dllName = Path.GetFileName(injectionProperties.DllPath);

            var module = injectionProperties.RemoteProcess.Modules.Find(m => m.Name == dllName);
            
            if (module.Equals(default(ModuleInstance)))
            {
                throw new ArgumentException($"No DLL with the name {dllName} was found in the target processes module list");
            }

            // Create a thread to call FreeLibraryAndExitThread in the target process

            var remoteThreadHandle = (SafeThreadHandle) injectionProperties.SyscallManager.InvokeSyscall<NtCreateThreadEx>(injectionProperties.RemoteProcess.Handle, freeLibraryAndExitThreadAddress, module.BaseAddress);

            PInvoke.WaitForSingleObject(remoteThreadHandle, uint.MaxValue);

            remoteThreadHandle.Dispose();

            return true;
        }
    }
}
