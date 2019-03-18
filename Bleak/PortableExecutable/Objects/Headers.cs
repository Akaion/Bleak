using Bleak.Native;
using System.Collections.Generic;

namespace Bleak.PortableExecutable.Objects
{
    internal class Headers
    {
        internal Structures.ImageDosHeader DosHeader;

        internal Structures.ImageFileHeader FileHeader;

        internal Structures.ImageNtHeaders32 NtHeaders32;

        internal Structures.ImageNtHeaders64 NtHeaders64;

        internal List<Structures.ImageSectionHeader> SectionHeaders;
    }
}
