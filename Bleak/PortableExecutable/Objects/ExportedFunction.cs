namespace Bleak.PortableExecutable.Objects
{
    internal class ExportedFunction
    {
        internal readonly uint Offset;

        internal readonly string Name;

        internal readonly ushort Ordinal;

        internal ExportedFunction(uint offset, string name, ushort ordinal)
        {
            Offset = offset;

            Name = name;

            Ordinal = ordinal;
        }
    }
}
