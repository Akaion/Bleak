using Bleak.Extensions.Interfaces;
using Bleak.Native;
using Bleak.Tools;
using Bleak.Wrappers;
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Bleak.Extensions
{
    internal class RandomiseHeaders : IExtensionMethod
    {
        private readonly PropertyWrapper PropertyWrapper;

        internal RandomiseHeaders(PropertyWrapper propertyWrapper)
        {
            PropertyWrapper = propertyWrapper;
        }

        public bool Call()
        {
            var dllName = Path.GetFileName(PropertyWrapper.DllPath);

            // Get an instance of the DLL in the target process

            var module = NativeTools.GetProcessModules(PropertyWrapper.Process.Id).FirstOrDefault(m => m.Module.Equals(dllName, StringComparison.OrdinalIgnoreCase));

            if (module.Equals(default))
            {
                throw new ArgumentException($"Failed to find {dllName} in the target processes module list");
            }

            // Get the information about the header region of the DLL in the target process

            var memoryInformationBuffer = (IntPtr) PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtQueryVirtualMemory>(PropertyWrapper.ProcessHandle.Value, module.BaseAddress);

            // Marshal the information from the buffer

            var memoryInformation = Marshal.PtrToStructure<Structures.MemoryBasicInformation>(memoryInformationBuffer);

            // Write over the header region of the DLL with a buffer of zeroes

            var buffer = new byte[(int)memoryInformation.RegionSize];

            new Random().NextBytes(buffer);

            PropertyWrapper.MemoryManager.Value.WriteMemory(module.BaseAddress, buffer);

            return true;
        }
    }
}
