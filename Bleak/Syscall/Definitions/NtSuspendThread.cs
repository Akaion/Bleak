using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Handlers;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtSuspendThread : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtSuspendThreadDefinition(SafeThreadHandle threadHandle, IntPtr previousSuspendCountBuffer);

        private readonly NtSuspendThreadDefinition NtSuspendThreadDelegate;

        private readonly Tools SyscallTools;

        internal NtSuspendThread(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtSuspendThreadDelegate = SyscallTools.CreateDelegateForSyscall<NtSuspendThreadDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtSuspendThreadDelegate);
        }

        internal void Invoke(SafeThreadHandle threadHandle)
        {
            // Perform the syscall

            var syscallResult = NtSuspendThreadDelegate(threadHandle, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the target process", syscallResult);
            }
        }
    }
}
