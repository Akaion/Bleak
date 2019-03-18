using Bleak.Native;
using Bleak.PortableExecutable.Objects;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Bleak.PortableExecutable
{
    internal class PortableExecutableParser : IDisposable
    {
        private readonly Lazy<Stream> DllStream;
        
        private readonly Lazy<Headers> PeHeaders;

        private readonly Tools PeTools;

        internal PortableExecutableParser(byte[] dllBytes)
        {
            DllStream = new Lazy<Stream>(() => new MemoryStream(dllBytes));

            PeHeaders = new Lazy<Headers>(ReadHeaders);

            PeTools = new Tools(DllStream, PeHeaders);
        }

        internal PortableExecutableParser(string dllPath)
        {
            DllStream = new Lazy<Stream>(() => new FileStream(dllPath, FileMode.Open, FileAccess.Read));

            PeHeaders = new Lazy<Headers>(ReadHeaders);

            PeTools = new Tools(DllStream, PeHeaders);
        }

        public void Dispose()
        {
            DllStream.Value.Dispose();

            PeTools.Dispose();
        }
        
        internal IEnumerable<BaseRelocation> GetBaseRelocations()
        {
            var peHeaders = PeHeaders.Value;

            // Calculate the file offset of the base relocation table

            var baseRelocationRva = peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? peHeaders.NtHeaders32.OptionalHeader.DataDirectory[5].VirtualAddress : peHeaders.NtHeaders64.OptionalHeader.DataDirectory[5].VirtualAddress;

            var baseRelocationTableOffset = PeTools.ConvertRvaToFileOffset(baseRelocationRva);
            
            while (true)
            {
                // Read the base relocation from the stream

                var baseRelocation = PeTools.ReadStructureFromStream<Structures.ImageBaseRelocation>(baseRelocationTableOffset);

                if (baseRelocation.SizeOfBlock == 0)
                {
                    break;
                }

                // Calculate the amount of type offsets the base relocation has

                var typeOffsetAmount = (baseRelocation.SizeOfBlock - 8) / sizeof(ushort);

                // Calculate the file offset of the type offsets

                var typeOffsetsOffset = baseRelocationTableOffset + Marshal.SizeOf<Structures.ImageBaseRelocation>();

                var typeOffsets = new List<TypeOffset>();

                for (var index = 0; index < typeOffsetAmount; index += 1)
                {
                    // Read the type offset from the stream

                    var typeOffset = PeTools.ReadStructureFromStream<ushort>((uint) (typeOffsetsOffset + sizeof(ushort) * index));

                    // The offset is located in the upper 12 bits of the type offset

                    var offset = typeOffset & 0xFFF;

                    // The type is located in the lower 4 bits of the type offset

                    var type = typeOffset >> 12;

                    typeOffsets.Add(new TypeOffset((ushort) offset, (Enumerations.RelocationType) type));
                }

                // Calculate the file offset of the base relocation

                var baseRelocationOffset = PeTools.ConvertRvaToFileOffset(baseRelocation.VirtualAddress);

                yield return new BaseRelocation(baseRelocationOffset, typeOffsets);

                // Calculate the file offset of the next base relocation

                baseRelocationTableOffset += baseRelocation.SizeOfBlock;
            }
        }

        internal IEnumerable<ExportedFunction> GetExportedFunctions()
        {
            var peHeaders = PeHeaders.Value;

            // Calculate the file offset of the export directory

            var exportDirectoryRva = peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? peHeaders.NtHeaders32.OptionalHeader.DataDirectory[0].VirtualAddress : peHeaders.NtHeaders64.OptionalHeader.DataDirectory[0].VirtualAddress;

            var exportDirectoryOffset = PeTools.ConvertRvaToFileOffset(exportDirectoryRva);

            // Read the export directory from the stream

            var exportDirectory = PeTools.ReadStructureFromStream<Structures.ImageExportDirectory>(exportDirectoryOffset);

            if (exportDirectory.NumberOfFunctions == 0)
            {
                yield break;
            }

            // Calculate the file offset of the exported function offsets

            var exportedFunctionOffsetsOffset = PeTools.ConvertRvaToFileOffset(exportDirectory.AddressOfFunctions);

            var exportedFunctions = new List<ExportedFunction>();

            for (var index = 0; index < exportDirectory.NumberOfFunctions; index += 1)
            {
                // Read the file offset of the exported function from the stream

                var exportedFunctionOffset = PeTools.ReadStructureFromStream<uint>((uint) (exportedFunctionOffsetsOffset + sizeof(uint) * index));

                // Calculate the ordinal of the exported function

                var exportedFunctionOrdinal = exportDirectory.Base + index;

                exportedFunctions.Add(new ExportedFunction(exportedFunctionOffset, null, (ushort) exportedFunctionOrdinal));
            }

            // Calculate the file offset of the exported function names

            var exportedFunctionNamesOffset = PeTools.ConvertRvaToFileOffset(exportDirectory.AddressOfNames);

            // Calculate the file offset of the exported function ordinals

            var exportedFunctionOrdinalsOffset = PeTools.ConvertRvaToFileOffset(exportDirectory.AddressOfNameOrdinals);

            for (var index = 0; index < exportDirectory.NumberOfNames; index += 1)
            {
                // Calculate the file offset of the exported functions name

                var exportedFunctionNameRva = PeTools.ReadStructureFromStream<uint>((uint) (exportedFunctionNamesOffset + sizeof(uint) * index));

                var exportedFunctionNameOffset = PeTools.ConvertRvaToFileOffset(exportedFunctionNameRva);

                // Read the name of the exported function from the stream

                var exportedFunctionName = PeTools.ReadStringFromStream(exportedFunctionNameOffset);

                // Read the ordinal of the exported function from the stream

                var exportedFunctionOrdinal = exportDirectory.Base + PeTools.ReadStructureFromStream<ushort>((uint) (exportedFunctionOrdinalsOffset + sizeof(ushort) * index));

                // Find the exported function that matches the ordinal
                
                var exportedFunction = exportedFunctions.First(f => f.Ordinal == exportedFunctionOrdinal);

                // Associate the exported functions name with the exported function

                yield return new ExportedFunction(exportedFunction.Offset, exportedFunctionName, exportedFunction.Ordinal);
            }
        }

        internal IEnumerable<ImportedFunction> GetImportedFunctions()
        {
            var peHeaders = PeHeaders.Value;

            // Calculate the file offset of the first import descriptor

            var importDescriptorRva = peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? peHeaders.NtHeaders32.OptionalHeader.DataDirectory[1].VirtualAddress : peHeaders.NtHeaders64.OptionalHeader.DataDirectory[1].VirtualAddress;

            var importDescriptorOffset = PeTools.ConvertRvaToFileOffset(importDescriptorRva);

            while (true)
            {
                // Read the import descriptor from the stream

                var importDescriptor = PeTools.ReadStructureFromStream<Structures.ImageImportDescriptor>(importDescriptorOffset);

                if (importDescriptor.OriginalFirstThunk == 0)
                {
                    break;
                }

                // Calculate the file offset the imported dll's name

                var importedDllNameOffset = PeTools.ConvertRvaToFileOffset(importDescriptor.Name);

                // Read the name of the imported dll from the stream

                var importedDllName = PeTools.ReadStringFromStream(importedDllNameOffset);

                // Calculate the file offset of the first thunk of the import descriptor

                var thunkOffset = PeTools.ConvertRvaToFileOffset(importDescriptor.FirstThunk);

                // Calculate the file offset of the data of the original first thunk of the import descriptor

                var originalThunkDataOffset = PeTools.ConvertRvaToFileOffset(importDescriptor.OriginalFirstThunk);

                while (true)
                {
                    // Read the thunk data of the import from the stream

                    var thunkData = PeTools.ReadStructureFromStream<Structures.ImageThunkData>(originalThunkDataOffset);

                    if (thunkData.AddressOfData == 0)
                    {
                        break;
                    }

                    // Calculate the file offset of the imported function

                    var importedFunctionOffset = PeTools.ConvertRvaToFileOffset(thunkData.AddressOfData);

                    // Read the name of the imported function from the stream

                    var importedFunctionName = PeTools.ReadStringFromStream(importedFunctionOffset + sizeof(ushort));

                    yield return new ImportedFunction(importedDllName, importedFunctionName, thunkOffset);

                    // Calculate the file offset of the next imports offset

                    thunkOffset += peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? (uint) sizeof(uint) : sizeof(ulong);

                    // Calculate the file offset of the next imports thunk data

                    originalThunkDataOffset += peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? (uint) sizeof(uint) : sizeof(ulong);
                }

                // Calculate the file offset of the next import descriptor

                importDescriptorOffset += (uint) Marshal.SizeOf<Structures.ImageImportDescriptor>();
            }
        }

        internal Enumerations.MachineType GetPeArchitecture()
        {
            return PeHeaders.Value.FileHeader.Machine;
        }

        internal Headers GetPeHeaders()
        {
            return PeHeaders.Value;
        }

        private Headers ReadHeaders()
        {
            var peHeaders = new Headers
            {
                // Read the dos header from the stream

                DosHeader = PeTools.ReadStructureFromStream<Structures.ImageDosHeader>(0),

                SectionHeaders = new List<Structures.ImageSectionHeader>()
            };

            if (peHeaders.DosHeader.e_magic != 0x5A4D)
            {
                throw new BadImageFormatException("The headers of the provided DLL were invalid");
            }

            // Read the file header from the stream

            peHeaders.FileHeader = PeTools.ReadStructureFromStream<Structures.ImageFileHeader>((uint) peHeaders.DosHeader.e_lfanew + sizeof(uint));

            if ((peHeaders.FileHeader.Characteristics & (ushort) Enumerations.FileCharacteristics.Dll) == 0)
            {
                throw new BadImageFormatException("The headers of the provided DLL were invalid");
            }
            
            // Read the nt headers from the stream

            switch (peHeaders.FileHeader.Machine)
            {
                case Enumerations.MachineType.X86:
                {
                    peHeaders.NtHeaders32 = PeTools.ReadStructureFromStream<Structures.ImageNtHeaders32>(peHeaders.DosHeader.e_lfanew);
                    
                    break;
                }

                case Enumerations.MachineType.X64:
                {
                    peHeaders.NtHeaders64 = PeTools.ReadStructureFromStream<Structures.ImageNtHeaders64>(peHeaders.DosHeader.e_lfanew);
                    
                    break;
                }

                default:
                {
                    throw new BadImageFormatException("The architecture of provided DLL was invalid");
                }    
            }
            
            // Calculate the file offset of the section headers

            var sectionHeadersOffset = peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? peHeaders.DosHeader.e_lfanew + Marshal.SizeOf<Structures.ImageNtHeaders32>() : peHeaders.DosHeader.e_lfanew + Marshal.SizeOf<Structures.ImageNtHeaders64>();

            // Read the section headers from the stream

            for (var index = 0; index < peHeaders.FileHeader.NumberOfSections; index += 1)
            {
                peHeaders.SectionHeaders.Add(PeTools.ReadStructureFromStream<Structures.ImageSectionHeader>((uint) (sectionHeadersOffset + Marshal.SizeOf<Structures.ImageSectionHeader>() * index)));
            }

            return peHeaders;
        }
    }
}
