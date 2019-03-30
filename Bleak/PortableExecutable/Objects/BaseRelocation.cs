using System.Collections.Generic;

namespace Bleak.PortableExecutable.Objects
{
    internal class BaseRelocation
    {
        internal readonly ulong Offset;

        internal readonly List<TypeOffset> TypeOffsets;

        internal BaseRelocation(ulong offset, List<TypeOffset> typeOffsets)
        {
            Offset = offset;

            TypeOffsets = typeOffsets;
        }
    }
}
