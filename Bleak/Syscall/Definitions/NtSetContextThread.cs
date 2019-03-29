using Bleak.Handlers;
using Bleak.Native;
using Bleak.SafeHandle;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtSetThreadContext
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtSetContextThreadDefinition(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        private readonly NtSetContextThreadDefinition _ntSetContextThreadDelegate;

        internal NtSetThreadContext(Tools syscallTools)
        {
            _ntSetContextThreadDelegate = syscallTools.CreateDelegateForSyscall<NtSetContextThreadDefinition>();
        }

        internal void Invoke(SafeThreadHandle threadHandle, IntPtr contextBuffer)
        {
            // Perform the syscall

            var syscallResult = _ntSetContextThreadDelegate(threadHandle, contextBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the target process", syscallResult);
            }
        }
    }
}
