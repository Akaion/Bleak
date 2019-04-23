using Bleak.Handlers;
using Bleak.Native;
using Bleak.Native.SafeHandle;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtSuspendThread
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtSuspendThreadDefinition(SafeThreadHandle threadHandle, IntPtr previousSuspendCountBuffer);

        private readonly NtSuspendThreadDefinition _ntSuspendThreadDelegate;

        internal NtSuspendThread(IntPtr shellcodeAddress)
        {
            _ntSuspendThreadDelegate = Marshal.GetDelegateForFunctionPointer<NtSuspendThreadDefinition>(shellcodeAddress);
        }

        internal void Invoke(SafeThreadHandle threadHandle)
        {
            // Perform the syscall

            var syscallResult = _ntSuspendThreadDelegate(threadHandle, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the target process", syscallResult);
            }
        }
    }
}
