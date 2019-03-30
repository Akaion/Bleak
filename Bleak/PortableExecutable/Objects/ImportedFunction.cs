namespace Bleak.PortableExecutable.Objects
{
    internal class ImportedFunction
    {
        internal readonly string DllName;

        internal readonly string Name;

        internal readonly ulong Offset;

        internal ImportedFunction(string dllName, string name, ulong offset)
        {
            DllName = dllName;

            Name = name;

            Offset = offset;
        }
    }
}
