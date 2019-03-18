using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Handlers;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtResumeThread : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtResumeThreadDefinition(SafeThreadHandle threadHandle, IntPtr previousSuspendCountBuffer);

        private readonly NtResumeThreadDefinition NtResumeThreadDelegate;

        private readonly Tools SyscallTools;

        internal NtResumeThread(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtResumeThreadDelegate = SyscallTools.CreateDelegateForSyscall<NtResumeThreadDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtResumeThreadDelegate);
        }

        internal void Invoke(SafeThreadHandle threadHandle)
        {
            // Perform the syscall

            var syscallResult = NtResumeThreadDelegate(threadHandle, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to resume a thread in the target process", syscallResult);
            }
        }
    }
}
