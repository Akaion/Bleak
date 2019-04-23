using Bleak.Handlers;
using Bleak.Memory;
using Bleak.Native;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtProtectVirtualMemory
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtProtectVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddressBuffer, IntPtr sizeBuffer, Enumerations.MemoryProtectionType protectionType, IntPtr oldProtectionBuffer);

        private readonly NtProtectVirtualMemoryDefinition _ntProtectVirtualMemoryDelegate;

        internal NtProtectVirtualMemory(IntPtr shellcodeAddress)
        {
            _ntProtectVirtualMemoryDelegate = Marshal.GetDelegateForFunctionPointer<NtProtectVirtualMemoryDefinition>(shellcodeAddress);
        }

        internal Enumerations.MemoryProtectionType Invoke(SafeProcessHandle processHandle, IntPtr baseAddress, int size, Enumerations.MemoryProtectionType protectionType)
        {
            // Store the base address of the memory region to protect in a buffer

            var baseAddressBuffer = LocalMemoryTools.StoreStructureInBuffer(baseAddress);

            // Store the protection size in a buffer

            var sizeBuffer = LocalMemoryTools.StoreStructureInBuffer(size);

            // Initialise a buffer to store the returned old protection of the memory region

            var oldProtectionBuffer = LocalMemoryTools.AllocateMemoryForBuffer(sizeof(ulong));

            // Perform the syscall

            var syscallResult = _ntProtectVirtualMemoryDelegate(processHandle, baseAddressBuffer, sizeBuffer, protectionType, oldProtectionBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to protect memory in the target process", syscallResult);
            }

            try
            {
                return (Enumerations.MemoryProtectionType) Marshal.PtrToStructure<ulong>(oldProtectionBuffer);
            }

            finally
            {
                LocalMemoryTools.FreeMemoryForBuffer(baseAddressBuffer);

                LocalMemoryTools.FreeMemoryForBuffer(sizeBuffer);

                LocalMemoryTools.FreeMemoryForBuffer(oldProtectionBuffer);
            }
        }
    }
}