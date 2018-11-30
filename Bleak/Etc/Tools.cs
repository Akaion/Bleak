using System;
using System.Runtime.InteropServices;

namespace Bleak.Etc
{
    internal static class Tools
    {
        internal static TStructure PointerToStructure<TStructure>(IntPtr pointer)
        {
            // Get the structure representation of the specified pointer
            
            var structure = (TStructure) Marshal.PtrToStructure(pointer, typeof(TStructure));

            return structure;
        }
    }
}