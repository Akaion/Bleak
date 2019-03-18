using System.Collections.Generic;

namespace Bleak.PortableExecutable.Objects
{
    internal class BaseRelocation
    {
        internal readonly uint Offset;

        internal readonly List<TypeOffset> TypeOffsets;

        internal BaseRelocation(uint offset, List<TypeOffset> typeOffsets)
        {
            Offset = offset;

            TypeOffsets = typeOffsets;
        }
    }
}
