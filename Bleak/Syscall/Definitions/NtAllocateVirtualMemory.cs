using Bleak.Handlers;
using Bleak.Native;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtAllocateVirtualMemory
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtAllocateVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddressBuffer, ulong zeroBits, IntPtr allocationSizeBuffer, Enumerations.MemoryAllocationType allocationType, Enumerations.MemoryProtectionType protectionType);

        private readonly NtAllocateVirtualMemoryDefinition _ntAllocateVirtualMemoryDelegate;

        internal NtAllocateVirtualMemory(Tools syscallTools)
        {
            _ntAllocateVirtualMemoryDelegate = syscallTools.CreateDelegateForSyscall<NtAllocateVirtualMemoryDefinition>();
        }

        internal IntPtr Invoke(SafeProcessHandle processHandle, int allocationSize, Enumerations.MemoryProtectionType protectionType)
        {
            // Initialise a buffer to store the returned address of the allocated memory region

            var memoryRegionAddressBuffer = MemoryTools.AllocateMemoryForBuffer(IntPtr.Size);

            // Store the size of the allocation in a buffer

            var allocationSizeBuffer = MemoryTools.StoreStructureInBuffer(allocationSize);

            // Perform the syscall

            const Enumerations.MemoryAllocationType allocationType = Enumerations.MemoryAllocationType.Commit | Enumerations.MemoryAllocationType.Reserve;

            var syscallResult = _ntAllocateVirtualMemoryDelegate(processHandle, memoryRegionAddressBuffer, 0, allocationSizeBuffer, allocationType, protectionType);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate memory in the target process", syscallResult);
            }

            // Marshal the returned address of the memory region from the buffer

            var memoryRegionAddress = Marshal.PtrToStructure<IntPtr>(memoryRegionAddressBuffer);

            MemoryTools.FreeMemoryForBuffer(memoryRegionAddressBuffer);

            MemoryTools.FreeMemoryForBuffer(allocationSizeBuffer);

            return memoryRegionAddress;
        }
    }
}
