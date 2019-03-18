using Bleak.Native;
using Bleak.Handlers;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtProtectVirtualMemory : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtProtectVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddressBuffer, IntPtr protectionSizeBuffer, Enumerations.MemoryProtectionType newProtectionType, IntPtr oldProtectionBuffer);

        private readonly NtProtectVirtualMemoryDefinition NtProtectVirtualMemoryDelegate;

        private readonly Tools SyscallTools;

        internal NtProtectVirtualMemory(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtProtectVirtualMemoryDelegate = SyscallTools.CreateDelegateForSyscall<NtProtectVirtualMemoryDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtProtectVirtualMemoryDelegate);
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

            var syscallResult = NtProtectVirtualMemoryDelegate(processHandle, baseAddressBuffer, protectionSizeBuffer, newProtectionType, oldProtectionBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to protect memory in the target process", syscallResult);
            }

            // Marshal the returned old protection of the memory region from the buffer

            var oldProtection = (Enumerations.MemoryProtectionType) Marshal.PtrToStructure<ulong>(oldProtectionBuffer);

            // Free the memory allocated for the buffers

            MemoryTools.FreeMemoryForBuffer(baseAddressBuffer, IntPtr.Size);

            MemoryTools.FreeMemoryForBuffer(protectionSizeBuffer, sizeof(int));

            MemoryTools.FreeMemoryForBuffer(oldProtectionBuffer, sizeof(ulong));

            return oldProtection;
        }
    }
}
