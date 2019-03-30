namespace Bleak.PortableExecutable.Objects
{
    internal class ExportedFunction
    {
        internal string Name;

        internal readonly ulong Offset;

        internal readonly ushort Ordinal;

        internal ExportedFunction(string name, ulong offset, ushort ordinal)
        {
            Name = name;

            Offset = offset;

            Ordinal = ordinal;
        }
    }
}
