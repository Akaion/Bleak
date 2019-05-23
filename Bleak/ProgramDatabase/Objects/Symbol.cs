namespace Bleak.ProgramDatabase.Objects
{
    internal class Symbol
    {
        internal readonly string Name;
        
        internal readonly uint Offset;

        internal readonly uint Section;

        internal Symbol(string name, uint offset, uint section)
        {
            Name = name;

            Offset = offset;

            Section = section;
        }
    }
}