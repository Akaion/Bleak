namespace Bleak.PortableExecutable.Objects
{
    internal class ApiSetMapping
    {
        internal readonly string VirtualDll;

        internal readonly string MappedToDll;

        internal ApiSetMapping(string apiSetDll, string mappedToDll)
        {
            VirtualDll = apiSetDll;

            MappedToDll = mappedToDll;
        }
    }
}
