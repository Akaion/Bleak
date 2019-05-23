namespace Bleak.Native
{
    internal static class Constants
    {
        internal const int DllProcessAttach = 0x01;

        internal const int DllProcessDetach = 0x00;

        internal const int DosSignature = 0x5A4D;

        internal const int NtSignature = 0x4550;

        internal const uint OrdinalFlag32 = 0x80000000;

        internal const ulong OrdinalFlag64 = 0x8000000000000000;

        internal const int SymbolMagic = 0x110E;
    }
}