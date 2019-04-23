using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native.SafeHandle;
using Bleak.Syscall.Definitions;
using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Bleak.Injection.Methods
{
    internal class QueueUserApc : IInjectionMethod
    {
        public bool Call(InjectionProperties injectionProperties)
        {
            // Get the address of the LoadLibraryW function in the target process

            var loadLibraryAddress = injectionProperties.RemoteProcess.GetFunctionAddress("kernel32.dll", "LoadLibraryW");

            // Write the DLL path into the target process

            var dllPathBuffer = injectionProperties.MemoryManager.AllocateVirtualMemory(IntPtr.Zero, injectionProperties.DllPath.Length, Native.Enumerations.MemoryProtectionType.ExecuteReadWrite);

            var dllPathBytes = Encoding.Unicode.GetBytes(injectionProperties.DllPath);

            injectionProperties.MemoryManager.WriteVirtualMemory(dllPathBuffer, dllPathBytes);

            foreach (var thread in injectionProperties.RemoteProcess.TargetProcess.Threads.Cast<ProcessThread>())
            {
                using (var threadHandle = (SafeThreadHandle) injectionProperties.SyscallManager.InvokeSyscall<NtOpenThread>(thread.Id))
                {
                    // Add an APC to call LoadLibraryW to the APC queue of the thread

                    injectionProperties.SyscallManager.InvokeSyscall<NtQueueApcThread>(threadHandle, loadLibraryAddress, dllPathBuffer);
                }
            }

            injectionProperties.MemoryManager.FreeVirtualMemory(dllPathBuffer);

            return true;
        }
    }
}
