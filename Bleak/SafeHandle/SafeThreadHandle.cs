using Bleak.Native;
using Bleak.Handlers;
using Microsoft.Win32.SafeHandles;
using System;

namespace Bleak.SafeHandle
{
    internal class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeThreadHandle() : base(true) { }

        internal SafeThreadHandle(IntPtr threadHandle, bool ownsHandle) : base(ownsHandle)
        {
            SetHandle(threadHandle);
        }

        protected override bool ReleaseHandle()
        {
            if (handle == IntPtr.Zero)
            {
                return false;
            }

            if (!PInvoke.CloseHandle(handle))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to close a handle to a snapshot");
            }

            return true;
        }
    }
}
