using Bleak.Handlers;
using Bleak.Native;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtFreeVirtualMemory
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtFreeVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddressBuffer, IntPtr freeSizeBuffer, Enumerations.MemoryFreeType freeType);

        private readonly NtFreeVirtualMemoryDefinition _ntFreeVirtualMemoryDelegate;

        internal NtFreeVirtualMemory(Tools syscallTools)
        {
            _ntFreeVirtualMemoryDelegate = syscallTools.CreateDelegateForSyscall<NtFreeVirtualMemoryDefinition>();
        }

        internal void Invoke(SafeProcessHandle processHandle, IntPtr baseAddress)
        {
            // Store the base address of memory region to free in a buffer

            var baseAddressBuffer = MemoryTools.StoreStructureInBuffer(baseAddress);

            // Store the free size in a buffer

            var freeSizeBuffer = MemoryTools.StoreStructureInBuffer(0);

            // Perform the syscall

            var syscallResult = _ntFreeVirtualMemoryDelegate(processHandle, baseAddressBuffer, freeSizeBuffer, Enumerations.MemoryFreeType.Release);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free memory in the target process", syscallResult);
            }

            MemoryTools.FreeMemoryForBuffer(baseAddressBuffer);

            MemoryTools.FreeMemoryForBuffer(freeSizeBuffer);
        }
    }
}
