using Bleak.Native;
using Bleak.Handlers;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtAllocateVirtualMemory : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtAllocateVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddressBuffer, ulong zeroBits, IntPtr allocationSizeBuffer, Enumerations.MemoryAllocationType allocationType, Enumerations.MemoryProtectionType protectionType);

        private readonly NtAllocateVirtualMemoryDefinition NtAllocateVirtualMemoryDelegate;

        private readonly Tools SyscallTools;

        internal NtAllocateVirtualMemory(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtAllocateVirtualMemoryDelegate = SyscallTools.CreateDelegateForSyscall<NtAllocateVirtualMemoryDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtAllocateVirtualMemoryDelegate);
        }
        
        internal IntPtr Invoke(SafeProcessHandle processHandle, int allocationSize, Enumerations.MemoryProtectionType protectionType)
        {
            // Initialise a buffer to store the returned address of the allocated memory region

            var memoryRegionAddressBuffer = MemoryTools.AllocateMemoryForBuffer(IntPtr.Size);

            // Store the size of the allocation in a buffer

            var allocationSizeBuffer = MemoryTools.StoreStructureInBuffer(allocationSize);

            // Perform the syscall

            const Enumerations.MemoryAllocationType allocationType = Enumerations.MemoryAllocationType.Commit | Enumerations.MemoryAllocationType.Reserve;

            var syscallResult = NtAllocateVirtualMemoryDelegate(processHandle, memoryRegionAddressBuffer, 0, allocationSizeBuffer, allocationType, protectionType);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate memory in the target process", syscallResult);
            }

            // Marshal the returned address of the memory region from the buffer

            var memoryRegionAddress = Marshal.PtrToStructure<IntPtr>(memoryRegionAddressBuffer);

            // Free the memory allocated for the buffers

            MemoryTools.FreeMemoryForBuffer(memoryRegionAddressBuffer, IntPtr.Size);

            MemoryTools.FreeMemoryForBuffer(allocationSizeBuffer, sizeof(int));

            return memoryRegionAddress;
        }
    }
}
