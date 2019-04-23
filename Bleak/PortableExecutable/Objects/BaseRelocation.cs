using System.Collections.Generic;

namespace Bleak.PortableExecutable.Objects
{
    internal class BaseRelocation
    {
        internal readonly ulong Offset;

        internal readonly List<Relocation> Relocations;

        internal BaseRelocation(ulong offset, List<Relocation> relocations)
        {
            Offset = offset;

            Relocations = relocations;
        }
    }
}
