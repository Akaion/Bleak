using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native;
using Bleak.RemoteProcess.Objects;
using Bleak.Syscall.Definitions;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Bleak.Injection.Extensions
{
    internal class RandomiseDllHeaders : IInjectionExtension
    {
        public bool Call(InjectionProperties injectionProperties)
        {
            // Look for the DLL in the module list of the target process

            var dllName = Path.GetFileName(injectionProperties.DllPath);

            var module = injectionProperties.RemoteProcess.Modules.Find(m => m.Name == dllName);

            if (module.Equals(default(ModuleInstance)))
            {
                throw new ArgumentException($"No DLL with the name {dllName} was found in the target processes module list");
            }

            // Query the header region of the DLL in the target process

            var memoryInformationBuffer = (IntPtr) injectionProperties.SyscallManager.InvokeSyscall<NtQueryVirtualMemory>(injectionProperties.RemoteProcess.Handle, module.BaseAddress);

            var memoryInformation = Marshal.PtrToStructure<Structures.MemoryBasicInformation>(memoryInformationBuffer);

            // Write over the header region with random bytes

            var randomBuffer = new byte[(int) memoryInformation.RegionSize];

            new Random().NextBytes(randomBuffer);

            injectionProperties.MemoryManager.WriteVirtualMemory(module.BaseAddress, randomBuffer);

            return true;
        }
    }
}
