using Bleak.Handlers;
using Bleak.Native;
using Bleak.SafeHandle;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtResumeThread
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtResumeThreadDefinition(SafeThreadHandle threadHandle, IntPtr previousSuspendCountBuffer);

        private readonly NtResumeThreadDefinition _ntResumeThreadDelegate;

        internal NtResumeThread(Tools syscallTools)
        {
            _ntResumeThreadDelegate = syscallTools.CreateDelegateForSyscall<NtResumeThreadDefinition>();
        }

        internal void Invoke(SafeThreadHandle threadHandle)
        {
            // Perform the syscall

            var syscallResult = _ntResumeThreadDelegate(threadHandle, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to resume a thread in the target process", syscallResult);
            }
        }
    }
}
