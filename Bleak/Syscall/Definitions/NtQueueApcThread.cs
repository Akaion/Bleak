using Bleak.Handlers;
using Bleak.Native;
using Bleak.Native.SafeHandle;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtQueueApcThread
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtQueueApcThreadDefinition(SafeThreadHandle threadHandle, IntPtr apcRoutine, IntPtr parameter, IntPtr statusBlockBuffer, ulong reserved);

        private readonly NtQueueApcThreadDefinition _ntQueueApcThreadDelegate;
        
        internal NtQueueApcThread(IntPtr shellcodeAddress)
        {
            _ntQueueApcThreadDelegate = Marshal.GetDelegateForFunctionPointer<NtQueueApcThreadDefinition>(shellcodeAddress);
        }

        internal void Invoke(SafeThreadHandle threadHandle, IntPtr apcRoutine, IntPtr parameter)
        {
            // Perform the syscall

            var syscallResult = _ntQueueApcThreadDelegate(threadHandle, apcRoutine, parameter, IntPtr.Zero, 0);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to queue an APC to the APC queue of a thread in the target process", syscallResult);
            }
        }
    }
}
