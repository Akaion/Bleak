using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Handlers;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtSetContextThread : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtSetContextThreadDefinition(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        private readonly NtSetContextThreadDefinition NtSetContextThreadDelegate;

        private readonly Tools SyscallTools;

        internal NtSetContextThread(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtSetContextThreadDelegate = SyscallTools.CreateDelegateForSyscall<NtSetContextThreadDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtSetContextThreadDelegate);
        }

        internal void Invoke(SafeThreadHandle threadHandle, IntPtr contextBuffer)
        {
            // Perform the syscall

            var syscallResult = NtSetContextThreadDelegate(threadHandle, contextBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the remote process", syscallResult);
            }
        }
    }
}
