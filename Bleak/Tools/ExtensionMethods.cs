using System;

namespace Bleak.Tools
{
    internal static class ExtensionMethods
    {
        internal static IntPtr AddOffset(this IntPtr pointer, long offset)
        {
            return (IntPtr) ((long) pointer + offset);
        }

        internal static IntPtr AddOffset(this IntPtr pointer, ulong offset)
        {
            return (IntPtr) ((ulong) pointer + offset);
        }
    }
}
