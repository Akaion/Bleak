namespace Bleak.PortableExecutable.Objects
{
    internal class DebugData
    {
        internal readonly uint Age;
        
        internal readonly string Guid;

        internal readonly string Name;

        internal DebugData(uint age, string guid, string name)
        {
            Age = age;

            Guid = guid;

            Name = name;
        }
    }
}