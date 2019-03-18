using Bleak.Native;
using Bleak.Handlers;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtFreeVirtualMemory : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtFreeVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddressBuffer, IntPtr freeSizeBuffer, Enumerations.MemoryFreeType freeType);

        private readonly NtFreeVirtualMemoryDefinition NtFreeVirtualMemoryDelegate;

        private readonly Tools SyscallTools;

        internal NtFreeVirtualMemory(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtFreeVirtualMemoryDelegate = SyscallTools.CreateDelegateForSyscall<NtFreeVirtualMemoryDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtFreeVirtualMemoryDelegate);
        }

        internal void Invoke(SafeProcessHandle processHandle, IntPtr baseAddress)
        {
            // Store the base address of memory region to free in a buffer

            var baseAddressBuffer = MemoryTools.StoreStructureInBuffer(baseAddress);

            // Store the free size in a buffer

            var freeSizeBuffer = MemoryTools.StoreStructureInBuffer(0);

            // Perform the syscall

            var syscallResult = NtFreeVirtualMemoryDelegate(processHandle, baseAddressBuffer, freeSizeBuffer, Enumerations.MemoryFreeType.Release);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free memory in the target process", syscallResult);
            }

            // Free the memory allocated for the buffers

            MemoryTools.FreeMemoryForBuffer(baseAddressBuffer, IntPtr.Size);

            MemoryTools.FreeMemoryForBuffer(freeSizeBuffer, sizeof(int));
        }
    }
}
