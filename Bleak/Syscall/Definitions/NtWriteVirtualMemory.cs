using Bleak.Native;
using Bleak.Handlers;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtWriteVirtualMemory : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtWriteVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bufferToWrite, ulong sizeOfBuffer, IntPtr bytesWrittenBuffer);

        private readonly NtWriteVirtualMemoryDefinition NtWriteVirtualMemoryDelegate;

        private readonly Tools SyscallTools;

        internal NtWriteVirtualMemory(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtWriteVirtualMemoryDelegate = SyscallTools.CreateDelegateForSyscall<NtWriteVirtualMemoryDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtWriteVirtualMemoryDelegate);
        }

        internal void Invoke(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bufferToWrite, int sizeOfBuffer)
        {
            // Perform the syscall

            var syscallResult = NtWriteVirtualMemoryDelegate(processHandle, baseAddress, bufferToWrite, (ulong) sizeOfBuffer, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write memory in the target process", syscallResult);
            }
        }
    }
}
