using Bleak.Methods.Interfaces;
using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Tools;
using Bleak.Wrappers;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Bleak.Methods
{
    internal class QueueUserApc : IInjectionMethod
    {
        private readonly PropertyWrapper PropertyWrapper;

        internal QueueUserApc(PropertyWrapper propertyWrapper)
        {
            PropertyWrapper = propertyWrapper;
        }

        public bool Call()
        {
            // Get the address of LoadLibraryW in the target process

            var loadLibraryAddress = NativeTools.GetFunctionAddress(PropertyWrapper, "kernel32.dll", "LoadLibraryW");

            // Allocate a buffer for the DLL path in the target process

            var dllPathBuffer = PropertyWrapper.MemoryManager.Value.AllocateMemory(PropertyWrapper.DllPath.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            // Write the DLL path into the buffer

            var dllPathBytes = Encoding.Unicode.GetBytes(PropertyWrapper.DllPath + "\0");

            PropertyWrapper.MemoryManager.Value.WriteMemory(dllPathBuffer, dllPathBytes);

            foreach (var thread in PropertyWrapper.Process.Threads.Cast<ProcessThread>())
            {
                // Open a handle to the thread

                var threadHandle = (SafeThreadHandle) PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtOpenThread>(thread.Id);

                // Add an apc to call LoadLibraryW to the apc queue of the thread

                PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtQueueApcThread>(threadHandle, loadLibraryAddress, dllPathBuffer);

                threadHandle.Dispose();
            }

            // Free the memory allocated for the buffer

            PropertyWrapper.MemoryManager.Value.FreeMemory(dllPathBuffer);

            return true;
        }
    }
}
