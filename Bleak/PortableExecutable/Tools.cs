using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Bleak.PortableExecutable
{
    internal class Tools : IDisposable
    {
        private readonly Lazy<Objects.Headers> PeHeaders;

        private readonly Lazy<Stream> Stream;

        internal Tools(Lazy<Stream> stream, Lazy<Objects.Headers> peHeaders)
        {
            PeHeaders = peHeaders;

            Stream = stream;
        }

        public void Dispose()
        {
            Stream.Value.Dispose();
        }

        internal uint ConvertRvaToFileOffset(uint rva)
        {
            // Look for the section header that holds the file offset for the relative virtual address

            var sectionHeader = PeHeaders.Value.SectionHeaders.First(section => section.VirtualAddress <= rva && section.VirtualAddress + section.VirtualSize > rva);

            // Calculate the file offset of the relative virtual address

            return sectionHeader.PointerToRawData + (rva - sectionHeader.VirtualAddress);
        }

        internal string ReadStringFromStream(uint stringOffset)
        {
            Stream.Value.Seek(stringOffset, SeekOrigin.Begin);

            // Read the bytes of the string from the stream

            var stringBytes = new List<byte>();

            while (true)
            {
                var currentByte = Stream.Value.ReadByte();

                if (currentByte == 0x00)
                {
                    break;
                }

                stringBytes.Add((byte) currentByte);
            }

            // Convert the bytes of the string into a string

            return Encoding.Default.GetString(stringBytes.ToArray());
        }

        internal TStructure ReadStructureFromStream<TStructure>(uint structureOffset) where TStructure : struct
        {
            Stream.Value.Seek(structureOffset, SeekOrigin.Begin);

            // Read the bytes of the structure from the stream

            var structureBytes = new byte[Marshal.SizeOf<TStructure>()];

            Stream.Value.Read(structureBytes, 0, Marshal.SizeOf<TStructure>());

            // Store the bytes of the structure in a buffer

            var structureBuffer = GCHandle.Alloc(structureBytes, GCHandleType.Pinned);

            // Marshal the structure from the buffer

            var structure = Marshal.PtrToStructure<TStructure>(structureBuffer.AddrOfPinnedObject());

            // Free the memory allocated for the buffer

            structureBuffer.Free();

            return structure;
        }
    }
}
