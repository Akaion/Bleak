namespace Bleak.PortableExecutable.Objects
{
    internal class ExportedFunction
    {
        internal string Name;

        internal readonly uint Offset;

        internal readonly ushort Ordinal;

        internal ExportedFunction(string name, uint offset, ushort ordinal)
        {
            Name = name;

            Offset = offset;

            Ordinal = ordinal;
        }
    }
}
