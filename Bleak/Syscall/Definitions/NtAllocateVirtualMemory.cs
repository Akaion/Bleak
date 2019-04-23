using Bleak.Handlers;
using Bleak.Memory;
using Bleak.Native;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtAllocateVirtualMemory
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtAllocateVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddressBuffer, ulong zeroBits, IntPtr sizeBuffer, Enumerations.MemoryAllocationType allocationType, Enumerations.MemoryProtectionType protectionType);

        private readonly NtAllocateVirtualMemoryDefinition _ntAllocateVirtualMemoryDelegate;

        internal NtAllocateVirtualMemory(IntPtr shellcodeAddress)
        {
            _ntAllocateVirtualMemoryDelegate = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemoryDefinition>(shellcodeAddress);
        }

        internal IntPtr Invoke(SafeProcessHandle processHandle, IntPtr baseAddress, int size, Enumerations.MemoryProtectionType protectionType)
        {
            // Store the base address of the allocation in a buffer

            var baseAddressBuffer = LocalMemoryTools.StoreStructureInBuffer(baseAddress);

            // Store the size of the allocation in a buffer

            var sizeBuffer = LocalMemoryTools.StoreStructureInBuffer(size);

            // Perform the syscall

            const Enumerations.MemoryAllocationType allocationType = Enumerations.MemoryAllocationType.Commit | Enumerations.MemoryAllocationType.Reserve;

            var syscallResult = _ntAllocateVirtualMemoryDelegate(processHandle, baseAddressBuffer, 0, sizeBuffer, allocationType, protectionType);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate memory in the target process", syscallResult);
            }

            try
            {
                return Marshal.PtrToStructure<IntPtr>(baseAddressBuffer);
            }

            finally
            {
                LocalMemoryTools.FreeMemoryForBuffer(baseAddressBuffer);

                LocalMemoryTools.FreeMemoryForBuffer(sizeBuffer);
            }
        }
    }
}
