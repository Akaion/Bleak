using Bleak.Native;

namespace Bleak.PortableExecutable.Objects
{
    internal class Relocation
    {
        internal readonly ushort Offset;

        internal readonly Enumerations.RelocationType Type;

        internal Relocation(ushort offset, Enumerations.RelocationType type)
        {
            Offset = offset;

            Type = type;
        }
    }
}
