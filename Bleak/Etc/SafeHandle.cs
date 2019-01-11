using System;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Etc
{
    internal class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeThreadHandle() : base(true) {}

        protected override bool ReleaseHandle()
        {
            return Native.CloseHandle(handle);
        }
    }
    
    internal class SafeModuleHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeModuleHandle() : base(true) {}

        protected override bool ReleaseHandle()
        {
            return Native.CloseHandle(handle);
        }
    }
    
    internal class SafeWindowHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeWindowHandle(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }
        
        protected override bool ReleaseHandle()
        {
            return Native.CloseHandle(handle);
        }
    }
}