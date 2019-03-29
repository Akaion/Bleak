using Bleak.Handlers;
using Bleak.Native;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtReadVirtualMemory
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtReadVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bytesReadBuffer, ulong bytesToRead, IntPtr numberOfBytesReadBuffer);

        private readonly NtReadVirtualMemoryDefinition _ntReadVirtualMemoryDelegate;

        internal NtReadVirtualMemory(Tools syscallTools)
        {
            _ntReadVirtualMemoryDelegate = syscallTools.CreateDelegateForSyscall<NtReadVirtualMemoryDefinition>();
        }

        internal IntPtr Invoke(SafeProcessHandle processHandle, IntPtr baseAddress, int bytesToRead)
        {
            // Initialise a buffer to store the returned bytes read

            var bytesReadBuffer = MemoryTools.AllocateMemoryForBuffer(bytesToRead);

            // Perform the syscall

            var syscallResult = _ntReadVirtualMemoryDelegate(processHandle, baseAddress, bytesReadBuffer, (ulong)bytesToRead, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to read memory from the target process", syscallResult);
            }

            return bytesReadBuffer;
        }
    }
}
