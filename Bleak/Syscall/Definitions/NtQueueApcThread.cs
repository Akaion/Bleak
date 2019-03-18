using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Handlers;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtQueueApcThread : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtQueueApcThreadDefinition(SafeThreadHandle threadHandle, IntPtr apcRoutine, IntPtr parameter, IntPtr statusBlockBuffer, ulong reserved);

        private readonly NtQueueApcThreadDefinition NtQueueApcThreadDelegate;

        private readonly Tools SyscallTools;

        internal NtQueueApcThread(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtQueueApcThreadDelegate = SyscallTools.CreateDelegateForSyscall<NtQueueApcThreadDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtQueueApcThreadDelegate);
        }

        internal void Invoke(SafeThreadHandle threadHandle, IntPtr apcRoutine, IntPtr parameter)
        {
            // Perform the syscall

            var syscallResult = NtQueueApcThreadDelegate(threadHandle, apcRoutine, parameter, IntPtr.Zero, 0);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to queue an apc to the apc queue of a thread in the target process", syscallResult);
            }
        }
    }
}
