namespace Bleak.PortableExecutable.Objects
{
    internal class ImportedFunction
    {
        internal readonly string DllName;

        internal readonly string Name;

        internal readonly uint Offset;

        internal ImportedFunction(string dllName, string name, uint offset)
        {
            DllName = dllName;

            Name = name;

            Offset = offset;
        }
    }
}
