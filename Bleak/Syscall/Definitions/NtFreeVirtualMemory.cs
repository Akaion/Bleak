using Bleak.Handlers;
using Bleak.Memory;
using Bleak.Native;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtFreeVirtualMemory
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtFreeVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddressBuffer, IntPtr sizeBuffer, Enumerations.MemoryFreeType freeType);

        private readonly NtFreeVirtualMemoryDefinition _ntFreeVirtualMemoryDelegate;

        internal NtFreeVirtualMemory(IntPtr shellcodeAddress)
        {
            _ntFreeVirtualMemoryDelegate = Marshal.GetDelegateForFunctionPointer<NtFreeVirtualMemoryDefinition>(shellcodeAddress);
        }

        internal void Invoke(SafeProcessHandle processHandle, IntPtr baseAddress)
        {
            // Store the base address of memory region to free in a buffer

            var baseAddressBuffer = LocalMemoryTools.StoreStructureInBuffer(baseAddress);

            // Store the free size in a buffer

            var sizeBuffer = LocalMemoryTools.StoreStructureInBuffer(0);

            // Perform the syscall

            var syscallResult = _ntFreeVirtualMemoryDelegate(processHandle, baseAddressBuffer, sizeBuffer, Enumerations.MemoryFreeType.Release);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free memory in the target process", syscallResult);
            }

            LocalMemoryTools.FreeMemoryForBuffer(baseAddressBuffer);

            LocalMemoryTools.FreeMemoryForBuffer(sizeBuffer);
        }
    }
}
