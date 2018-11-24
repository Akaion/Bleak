using System;
using System.Runtime.InteropServices;

namespace Simple_Injection.Etc
{
    internal static class Tools
    {
        internal static TStructure PointerToStructure<TStructure>(IntPtr pointer)
        {
            var structure = (TStructure) Marshal.PtrToStructure(pointer, typeof(TStructure));

            return structure;
        }
    }
}
