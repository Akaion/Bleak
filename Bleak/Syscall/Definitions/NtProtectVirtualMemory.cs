using Bleak.Handlers;
using Bleak.Native;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtProtectVirtualMemory
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtProtectVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddressBuffer, IntPtr protectionSizeBuffer, Enumerations.MemoryProtectionType newProtectionType, IntPtr oldProtectionBuffer);

        private readonly NtProtectVirtualMemoryDefinition _ntProtectVirtualMemoryDelegate;

        internal NtProtectVirtualMemory(Tools syscallTools)
        {
            _ntProtectVirtualMemoryDelegate = syscallTools.CreateDelegateForSyscall<NtProtectVirtualMemoryDefinition>();
        }

        internal Enumerations.MemoryProtectionType Invoke(SafeProcessHandle processHandle, IntPtr baseAddress, int protectionSize, Enumerations.MemoryProtectionType newProtectionType)
        {
            // Store the base address of the memory region to protect in a buffer

            var baseAddressBuffer = MemoryTools.StoreStructureInBuffer(baseAddress);

            // Store the protection size in a buffer

            var protectionSizeBuffer = MemoryTools.StoreStructureInBuffer(protectionSize);

            // Initialise a buffer to store the returned old protection of the memory region

            var oldProtectionBuffer = MemoryTools.AllocateMemoryForBuffer(sizeof(ulong));

            // Perform the syscall

            var syscallResult = _ntProtectVirtualMemoryDelegate(processHandle, baseAddressBuffer, protectionSizeBuffer, newProtectionType, oldProtectionBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to protect memory in the target process", syscallResult);
            }

            // Marshal the returned old protection of the memory region from the buffer

            var oldProtection = (Enumerations.MemoryProtectionType) Marshal.PtrToStructure<ulong>(oldProtectionBuffer);

            MemoryTools.FreeMemoryForBuffer(baseAddressBuffer);

            MemoryTools.FreeMemoryForBuffer(protectionSizeBuffer);

            MemoryTools.FreeMemoryForBuffer(oldProtectionBuffer);

            return oldProtection;
        }
    }
}
