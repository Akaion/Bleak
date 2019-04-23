using Bleak.Handlers;
using Bleak.Native;
using Bleak.Native.SafeHandle;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtSetContextThread
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtSetContextThreadDefinition(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        private readonly NtSetContextThreadDefinition _ntSetContextThreadDelegate;

        internal NtSetContextThread(IntPtr shellcodeAddress)
        {
            _ntSetContextThreadDelegate = Marshal.GetDelegateForFunctionPointer<NtSetContextThreadDefinition>(shellcodeAddress);
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
