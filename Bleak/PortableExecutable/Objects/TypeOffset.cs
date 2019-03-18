using Bleak.Native;

namespace Bleak.PortableExecutable.Objects
{
    internal class TypeOffset
    {
        internal readonly ushort Offset;

        internal readonly Enumerations.RelocationType Type;

        internal TypeOffset(ushort offset, Enumerations.RelocationType type)
        {
            Offset = offset;

            Type = type;
        }
    }
}
