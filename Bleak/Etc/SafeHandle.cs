using System;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Etc
{
    internal class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeThreadHandle() : base(true) {}
                
        protected override bool ReleaseHandle()
        {
            return handle != IntPtr.Zero && Native.CloseHandle(handle);
        }
    }
}