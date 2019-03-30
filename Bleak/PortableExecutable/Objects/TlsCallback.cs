namespace Bleak.PortableExecutable.Objects
{
    internal class TlsCallback
    {
        internal readonly ulong Offset;

        internal TlsCallback(ulong offset)
        {
            Offset = offset;
        }
    }
}
