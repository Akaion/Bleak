using Bleak.Native;
using Bleak.Handlers;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtReadVirtualMemory : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtReadVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddress, IntPtr bytesReadBuffer, ulong bytesToRead, IntPtr numberOfBytesReadBuffer);

        private readonly NtReadVirtualMemoryDefinition NtReadVirtualMemoryDelegate;

        private readonly Tools SyscallTools;

        internal NtReadVirtualMemory(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtReadVirtualMemoryDelegate = SyscallTools.CreateDelegateForSyscall<NtReadVirtualMemoryDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtReadVirtualMemoryDelegate);
        }

        internal IntPtr Invoke(SafeProcessHandle processHandle, IntPtr baseAddress, int bytesToRead)
        {
            // Initialise a buffer to store the returned bytes read

            var bytesReadBuffer = MemoryTools.AllocateMemoryForBuffer(bytesToRead);

            // Perform the syscall

            var syscallResult = NtReadVirtualMemoryDelegate(processHandle, baseAddress, bytesReadBuffer, (ulong) bytesToRead, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to read memory from the target process", syscallResult);
            }

            return bytesReadBuffer;
        }
    }
}
