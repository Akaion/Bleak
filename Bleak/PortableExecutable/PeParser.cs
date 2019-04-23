using Bleak.Memory;
using Bleak.Native;
using Bleak.PortableExecutable.Objects;
using Bleak.Tools;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Bleak.PortableExecutable
{
    internal class PeParser : IDisposable
    {
        private readonly IntPtr _dllBuffer;

        private readonly PeHeaders _peHeaders;

        internal PeParser(byte[] dllBytes)
        {
            _dllBuffer = LocalMemoryTools.StoreBytesInBuffer(dllBytes);

            _peHeaders = new PeHeaders();

            ReadPeHeaders();
        }

        internal PeParser(string dllPath)
        {
            _dllBuffer = LocalMemoryTools.StoreBytesInBuffer(File.ReadAllBytes(dllPath));

            _peHeaders = new PeHeaders();

            ReadPeHeaders();
        }

        public void Dispose()
        {
            LocalMemoryTools.FreeMemoryForBuffer(_dllBuffer);
        }

        private ulong ConvertRvaToOffset(ulong rva)
        {
            // Look for the section that holds the offset of the relative virtual address

            var sectionHeader = _peHeaders.SectionHeaders.Find(section => section.VirtualAddress <= rva && section.VirtualAddress + section.VirtualSize > rva);

            // Calculate the offset of the relative virtual address

            return sectionHeader.PointerToRawData + (rva - sectionHeader.VirtualAddress);
        }

        internal Enumerations.MachineType GetArchitecture()
        {
            return _peHeaders.FileHeader.Machine;
        }

        internal List<ApiSetMapping> GetApiSetMappings()
        {
            var apiSetMappings = new List<ApiSetMapping>();

            // Look for the .apiset section in the section headers of the DLL

            var apiSetSectionHeader = _peHeaders.SectionHeaders.Find(section => section.Name.SequenceEqual(Encoding.Default.GetBytes(".apiset\0")));

            if (apiSetSectionHeader.Equals(default(Structures.ImageSectionHeader)))
            {
                // The DLL has no .apiset section

                return apiSetMappings;
            }

            // Read the namespace of the API set

            var setDataAddress = _dllBuffer.AddOffset(apiSetSectionHeader.PointerToRawData);

            var setNamespace = Marshal.PtrToStructure<Structures.ApiSetNamespace>(setDataAddress);

            for (var index = 0; index < (int) setNamespace.Count; index += 1)
            {
                // Read the set entry of the API set

                var setEntry = Marshal.PtrToStructure<Structures.ApiSetNamespaceEntry>(setDataAddress.AddOffset(setNamespace.EntryOffset + Marshal.SizeOf<Structures.ApiSetNamespaceEntry>() * index));

                // Read the name of the set entry

                var setEntryName = string.Concat(Marshal.PtrToStringUni(setDataAddress.AddOffset(setEntry.NameOffset)), ".dll");

                // Read the value entry that the set entry maps to

                var valueEntry = Marshal.PtrToStructure<Structures.ApiSetValueEntry>(setDataAddress.AddOffset(setEntry.ValueOffset));

                // Read the name of the value entry

                var valueEntryNameBytes = new byte[valueEntry.ValueCount];

                Marshal.Copy(setDataAddress.AddOffset(valueEntry.ValueOffset), valueEntryNameBytes, 0, valueEntryNameBytes.Length);

                var valueEntryName = Encoding.Unicode.GetString(valueEntryNameBytes);

                apiSetMappings.Add(new ApiSetMapping(setEntryName, valueEntryName));
            }

            return apiSetMappings;
        }

        internal List<BaseRelocation> GetBaseRelocations()
        {
            var baseRelocations = new List<BaseRelocation>();

            // Calculate the offset of the base relocation table

            var baseRelocationTableRva = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86
                                       ? _peHeaders.NtHeaders32.OptionalHeader.DataDirectory[5].VirtualAddress
                                       : _peHeaders.NtHeaders64.OptionalHeader.DataDirectory[5].VirtualAddress;

            if (baseRelocationTableRva == 0)
            {
                // The DLL has no base relocations

                return baseRelocations;
            }

            var baseRelocationTableOffset = ConvertRvaToOffset(baseRelocationTableRva);

            while (true)
            {
                // Read the base relocation

                var baseRelocation = Marshal.PtrToStructure<Structures.ImageBaseRelocation>(_dllBuffer.AddOffset(baseRelocationTableOffset));

                if (baseRelocation.SizeOfBlock == 0)
                {
                    break;
                }

                // Calculate the offset of the relocations

                var relocationsOffset = baseRelocationTableOffset + (uint) Marshal.SizeOf<Structures.ImageBaseRelocation>();

                var relocations = new List<Relocation>();

                // Calculate the amount of relocations in the base relocation

                var relocationAmount = (baseRelocation.SizeOfBlock - 8) / sizeof(ushort);

                for (var index = 0; index < relocationAmount; index += 1)
                {
                    // Read the relocation

                    var relocation = Marshal.PtrToStructure<ushort>(_dllBuffer.AddOffset(relocationsOffset + (uint) (sizeof(ushort) * index)));

                    // The relocation offset is located in the upper 4 bits of the ushort

                    var relocationOffset = relocation & 0xFFF;

                    // The relocation type is located in the lower 12 bits of the ushort

                    var relocationType = relocation >> 12;

                    relocations.Add(new Relocation((ushort) relocationOffset, (Enumerations.RelocationType) relocationType));
                }

                baseRelocations.Add(new BaseRelocation(ConvertRvaToOffset(baseRelocation.VirtualAddress), relocations));

                // Calculate the offset of the next base relocation

                baseRelocationTableOffset += baseRelocation.SizeOfBlock;
            }

            return baseRelocations;
        }

        internal List<ExportedFunction> GetExportedFunctions()
        {
            var exportedFunctions = new List<ExportedFunction>();

            // Calculate the offset of the export directory

            var exportDirectoryRva = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86
                                   ? _peHeaders.NtHeaders32.OptionalHeader.DataDirectory[0].VirtualAddress
                                   : _peHeaders.NtHeaders64.OptionalHeader.DataDirectory[0].VirtualAddress;

            if (exportDirectoryRva == 0)
            {
                // The DLL has no exported functions

                return exportedFunctions;
            }

            var exportDirectoryOffset = ConvertRvaToOffset(exportDirectoryRva);

            // Read the export directory

            var exportDirectory = Marshal.PtrToStructure<Structures.ImageExportDirectory>(_dllBuffer.AddOffset(exportDirectoryOffset));

            // Calculate the offset of the exported functions offset

            var exportedFunctionOffsetsOffset = ConvertRvaToOffset(exportDirectory.AddressOfFunctions);

            for (var index = 0; index < exportDirectory.NumberOfFunctions; index += 1)
            {
                // Read the offset of the exported function

                var exportedFunctionOffset = Marshal.PtrToStructure<uint>(_dllBuffer.AddOffset(exportedFunctionOffsetsOffset + (uint) (sizeof(uint) * index)));

                exportedFunctions.Add(new ExportedFunction(null, exportedFunctionOffset, (ushort) (exportDirectory.Base + index)));
            }

            // Calculate the offset of the exported function names

            var exportedFunctionNamesOffset = ConvertRvaToOffset(exportDirectory.AddressOfNames);

            // Calculate the offset of the exported function ordinals

            var exportedFunctionOrdinalsOffset = ConvertRvaToOffset(exportDirectory.AddressOfNameOrdinals);

            for (var index = 0; index < exportDirectory.NumberOfNames; index += 1)
            {
                // Calculate the offset of the exported function name

                var exportedFunctionNameRva = Marshal.PtrToStructure<uint>(_dllBuffer.AddOffset(exportedFunctionNamesOffset + (uint) (sizeof(uint) * index)));

                var exportedFunctionNameOffset = ConvertRvaToOffset(exportedFunctionNameRva);

                // Read the name of the exported function

                var exportedFunctionName = Marshal.PtrToStringAnsi(_dllBuffer.AddOffset(exportedFunctionNameOffset));

                // Read the ordinal of the exported function

                var exportedFunctionOrdinal = exportDirectory.Base + Marshal.PtrToStructure<ushort>(_dllBuffer.AddOffset(exportedFunctionOrdinalsOffset + (uint) (sizeof(ushort) * index)));

                exportedFunctions.Find(f => f.Ordinal == exportedFunctionOrdinal).Name = exportedFunctionName;
            }

            return exportedFunctions;
        }

        internal PeHeaders GetHeaders()
        {
            return _peHeaders;
        }

        internal List<ImportedFunction> GetImportedFunctions()
        {
            var importedFunctions = new List<ImportedFunction>();

            // Calculate the offset of the first import descriptor

            var importDescriptorRva = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86
                                    ? _peHeaders.NtHeaders32.OptionalHeader.DataDirectory[1].VirtualAddress
                                    : _peHeaders.NtHeaders64.OptionalHeader.DataDirectory[1].VirtualAddress;

            if (importDescriptorRva == 0)
            {
                // The DLL has no imported functions

                return importedFunctions;
            }

            var importDescriptorOffset = ConvertRvaToOffset(importDescriptorRva);

            while (true)
            {
                // Read the import descriptor

                var importDescriptor = Marshal.PtrToStructure<Structures.ImageImportDescriptor>(_dllBuffer.AddOffset(importDescriptorOffset));

                if (importDescriptor.OriginalFirstThunk == 0)
                {
                    break;
                }

                // Read the name of the imported DLL

                var importedDllName = Marshal.PtrToStringAnsi(_dllBuffer.AddOffset(ConvertRvaToOffset(importDescriptor.Name)));

                // Calculate the offset of the original first thunk and first thunk

                var originalFirstThunkOffset = ConvertRvaToOffset(importDescriptor.OriginalFirstThunk);

                var firstThunkOffset = ConvertRvaToOffset(importDescriptor.FirstThunk);

                while (true)
                {
                    // Read the thunk of the imported function

                    var importedFunctionThunk = Marshal.PtrToStructure<Structures.ImageThunkData>(_dllBuffer.AddOffset(originalFirstThunkOffset));

                    if (importedFunctionThunk.AddressOfData == 0)
                    {
                        break;
                    }

                    // Read the name of the imported function

                    var importedFunctionName = Marshal.PtrToStringAnsi(_dllBuffer.AddOffset(ConvertRvaToOffset(importedFunctionThunk.AddressOfData) + sizeof(ushort)));

                    importedFunctions.Add(new ImportedFunction(importedDllName, importedFunctionName, firstThunkOffset));

                    // Calculate the offset of the next original first thunk and first thunk

                    originalFirstThunkOffset += _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? (uint) sizeof(uint) : sizeof(ulong);

                    firstThunkOffset += _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? (uint) sizeof(uint) : sizeof(ulong);
                }

                // Calculate the offset of the next import descriptor

                importDescriptorOffset += (uint) Marshal.SizeOf<Structures.ImageImportDescriptor>();
            }

            return importedFunctions;
        }

        internal IEnumerable<TlsCallback> GetTlsCallbacks()
        {
            // Calculate the offset of the TLS directory

            var tlsDirectoryRva = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86
                                ? _peHeaders.NtHeaders32.OptionalHeader.DataDirectory[9].VirtualAddress
                                : _peHeaders.NtHeaders64.OptionalHeader.DataDirectory[9].VirtualAddress;

            if (tlsDirectoryRva == 0)
            {
                // The DLL has no TLS callbacks

                yield break;
            }

            var tlsDirectoryOffset = ConvertRvaToOffset(tlsDirectoryRva);

            switch (_peHeaders.FileHeader.Machine)
            {
                case Enumerations.MachineType.X86:
                {
                    // Read the TLS directory

                    var tlsDirectory = Marshal.PtrToStructure<Structures.ImageTlsDirectory32>(_dllBuffer.AddOffset(tlsDirectoryOffset));

                    // Calculate the offset of the TLS callback RVA's

                    var tlsCallbacksOffset = ConvertRvaToOffset(tlsDirectory.AddressOfCallbacks - _peHeaders.NtHeaders32.OptionalHeader.ImageBase);

                    while (true)
                    {
                        // Calculate the offset of the TLS callback

                        var tlsCallback = Marshal.PtrToStructure<uint>(_dllBuffer.AddOffset(tlsCallbacksOffset));

                        if (tlsCallback == 0)
                        {
                            break;
                        }

                        var tlsCallbackOffset = ConvertRvaToOffset(tlsCallback - _peHeaders.NtHeaders32.OptionalHeader.ImageBase);

                        yield return new TlsCallback(tlsCallbackOffset);

                        // Calculate the offset of the next TLS callback RVA

                        tlsCallbacksOffset += sizeof(uint);
                    }

                    break;
                }
                
                case Enumerations.MachineType.X64:
                {
                    // Read the TLS directory

                    var tlsDirectory = Marshal.PtrToStructure<Structures.ImageTlsDirectory64>(_dllBuffer.AddOffset(tlsDirectoryOffset));

                    // Calculate the offset of the TLS callback RVA's

                    var tlsCallbacksOffset = ConvertRvaToOffset(tlsDirectory.AddressOfCallbacks - _peHeaders.NtHeaders64.OptionalHeader.ImageBase);

                    while (true)
                    {
                        // Calculate the offset of the TLS callback

                        var tlsCallback = Marshal.PtrToStructure<ulong>(_dllBuffer.AddOffset(tlsCallbacksOffset));

                        if (tlsCallback == 0)
                        {
                            break;
                        }

                        var tlsCallbackOffset = ConvertRvaToOffset(tlsCallback - _peHeaders.NtHeaders64.OptionalHeader.ImageBase);

                        yield return new TlsCallback(tlsCallbackOffset);

                        // Calculate the offset of the next TLS callback RVA

                        tlsCallbacksOffset += sizeof(ulong);
                    }

                    break;
                }
            }
        }

        private void ReadPeHeaders()
        {
            // Read the DOS header

            _peHeaders.DosHeader = Marshal.PtrToStructure<Structures.ImageDosHeader>(_dllBuffer);

            if (_peHeaders.DosHeader.e_magic != Constants.DosSignature)
            {
                throw new BadImageFormatException("The DOS header of the DLL was invalid");
            }

            // Read the file header

            _peHeaders.FileHeader = Marshal.PtrToStructure<Structures.ImageFileHeader>(_dllBuffer.AddOffset(_peHeaders.DosHeader.e_lfanew + sizeof(uint)));

            if (!_peHeaders.FileHeader.Characteristics.HasFlag(Enumerations.FileCharacteristics.Dll))
            {
                throw new BadImageFormatException("The file header of the DLL was invalid");
            }

            // Read the NT headers

            switch (_peHeaders.FileHeader.Machine)
            {
                case Enumerations.MachineType.X86:
                {
                    _peHeaders.NtHeaders32 = Marshal.PtrToStructure<Structures.ImageNtHeaders32>(_dllBuffer.AddOffset(_peHeaders.DosHeader.e_lfanew));
                    
                    if (_peHeaders.NtHeaders32.Signature != Constants.NtSignature)
                    {
                        throw new BadImageFormatException("The NT headers of the DLL were invalid");
                    }

                    if (_peHeaders.NtHeaders32.OptionalHeader.DataDirectory[14].VirtualAddress != 0)
                    {
                        throw new BadImageFormatException(".Net DLL's are not supported");
                    }

                    break;
                }
                
                case Enumerations.MachineType.X64:
                {
                    _peHeaders.NtHeaders64 = Marshal.PtrToStructure<Structures.ImageNtHeaders64>(_dllBuffer.AddOffset(_peHeaders.DosHeader.e_lfanew));
                    
                    if (_peHeaders.NtHeaders64.Signature != Constants.NtSignature)
                    {
                        throw new BadImageFormatException("The NT headers of the DLL were invalid");
                    }

                    if (_peHeaders.NtHeaders64.OptionalHeader.DataDirectory[14].VirtualAddress != 0)
                    {
                        throw new BadImageFormatException(".Net DLL's are not supported");
                    }

                    break;
                }
                
                default:
                {
                    throw new BadImageFormatException("The architecture of the DLL is not supported");
                }
            }

            // Read the section headers

            var sectionHeadersOffset = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86
                                     ? _peHeaders.DosHeader.e_lfanew + Marshal.SizeOf<Structures.ImageNtHeaders32>()
                                     : _peHeaders.DosHeader.e_lfanew + Marshal.SizeOf<Structures.ImageNtHeaders64>();

            for (var index = 0; index < _peHeaders.FileHeader.NumberOfSections; index += 1)
            {
                _peHeaders.SectionHeaders.Add(Marshal.PtrToStructure<Structures.ImageSectionHeader>(_dllBuffer.AddOffset(sectionHeadersOffset + Marshal.SizeOf<Structures.ImageSectionHeader>() * index)));
            }
        }
    }
}
