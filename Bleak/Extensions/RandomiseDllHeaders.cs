using Bleak.Native;
using Bleak.RemoteProcess.Objects;
using Bleak.Syscall.Definitions;
using Bleak.Wrappers;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Bleak.Extensions
{
    internal class RandomiseDllHeaders
    {
        private readonly PropertyWrapper _propertyWrapper;

        internal RandomiseDllHeaders(PropertyWrapper propertyWrapper)
        {
            _propertyWrapper = propertyWrapper;
        }

        internal bool Call()
        {
            var dllName = Path.GetFileName(_propertyWrapper.DllPath);

            // Look for the DLL in the module list of the target process

            var module = _propertyWrapper.TargetProcess.Modules.Find(m => m.Name == dllName);

            if (module.Equals(default(ModuleInstance)))
            {
                throw new ArgumentException($"No DLL with the name {dllName} was found in the target processes module list");
            }

            // Query the header region of the DLL in the target process

            var memoryInformationBuffer = (IntPtr) _propertyWrapper.SyscallManager.InvokeSyscall<NtQueryVirtualMemory>(_propertyWrapper.TargetProcess.Handle, module.BaseAddress);

            var memoryInformation = Marshal.PtrToStructure<Structures.MemoryBasicInformation>(memoryInformationBuffer);

            // Write over the header region with random bytes

            var randomBuffer = new byte[(int) memoryInformation.RegionSize];

            new Random().NextBytes(randomBuffer);

            _propertyWrapper.MemoryManager.WriteVirtualMemory(module.BaseAddress, randomBuffer);

            return true;
        }
    }
}
