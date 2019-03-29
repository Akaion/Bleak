using Bleak.Native;
using System.Collections.Generic;

namespace Bleak.PortableExecutable.Objects
{
    internal class PeHeaders
    {
        internal Structures.ImageDosHeader DosHeader;

        internal Structures.ImageFileHeader FileHeader;

        internal Structures.ImageNtHeaders32 NtHeaders32;

        internal Structures.ImageNtHeaders64 NtHeaders64;

        internal readonly List<Structures.ImageSectionHeader> SectionHeaders;

        internal PeHeaders()
        {
            SectionHeaders = new List<Structures.ImageSectionHeader>();
        }
    }
}
