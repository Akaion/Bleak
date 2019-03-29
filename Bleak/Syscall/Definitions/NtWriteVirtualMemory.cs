using Bleak.Handlers;
using Bleak.Native;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtWriteVirtualMemory
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtWriteVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bufferToWrite, ulong sizeOfBuffer, IntPtr bytesWrittenBuffer);

        private readonly NtWriteVirtualMemoryDefinition _ntWriteVirtualMemoryDelegate;

        internal NtWriteVirtualMemory(Tools syscallTools)
        {
            _ntWriteVirtualMemoryDelegate = syscallTools.CreateDelegateForSyscall<NtWriteVirtualMemoryDefinition>();
        }

        internal void Invoke(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bufferToWrite, int sizeOfBuffer)
        {
            // Perform the syscall

            var syscallResult = _ntWriteVirtualMemoryDelegate(processHandle, baseAddress, bufferToWrite, (ulong) sizeOfBuffer, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write memory in the target process", syscallResult);
            }
        }
    }
}
