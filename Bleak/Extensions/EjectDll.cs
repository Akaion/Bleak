using Bleak.Extensions.Interfaces;
using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Tools;
using Bleak.Wrappers;
using System;
using System.Collections.Generic;
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

            // Look for an instance of the DLL in the target process

            var module = GetModuleInstance(NativeTools.GetProcessModules(PropertyWrapper.Process.Id), dllName);

            if (module.Equals(default(Structures.ModuleEntry)))
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

        private static Structures.ModuleEntry GetModuleInstance(IEnumerable<Structures.ModuleEntry> processModules, string dllName)
        {
            // Look for an instance of the DLL in the target process

            var module = processModules.FirstOrDefault(m => m.Module.Equals(dllName, StringComparison.OrdinalIgnoreCase));

            if (module.Equals(default(Structures.ModuleEntry)))
            {
                // Check if the DLL is under a randomised name

                var temporaryDllPath = Directory.EnumerateFiles(Path.Combine(Path.GetTempPath(), "Bleak")).FirstOrDefault();

                if (temporaryDllPath is null)
                {
                    return module;
                }

                module = processModules.FirstOrDefault(m => m.Module.Equals(Path.GetFileName(temporaryDllPath), StringComparison.OrdinalIgnoreCase));
            }

            return module;
        }
    }
}
