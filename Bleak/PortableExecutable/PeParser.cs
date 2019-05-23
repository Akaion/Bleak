using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Bleak.Native;
using Bleak.PortableExecutable.Objects;
using Bleak.Shared;

namespace Bleak.PortableExecutable
{
    internal class PeParser : IDisposable
    {
        private readonly IntPtr _dllBuffer;

        private readonly GCHandle _dllBufferHandle;

        private readonly PeHeaders _peHeaders;

        internal PeParser(byte[] dllBytes)
        {
            _dllBufferHandle = GCHandle.Alloc(dllBytes.Clone(), GCHandleType.Pinned);
            
            _dllBuffer = _dllBufferHandle.AddrOfPinnedObject();

            _peHeaders = new PeHeaders();

            ReadPeHeaders();
        }

        internal PeParser(string dllPath)
        {
            _dllBufferHandle = GCHandle.Alloc(File.ReadAllBytes(dllPath), GCHandleType.Pinned);

            _dllBuffer = _dllBufferHandle.AddrOfPinnedObject();

            _peHeaders = new PeHeaders();

            ReadPeHeaders();
        }

        public void Dispose()
        {
            _dllBufferHandle.Free();
        }

        internal Enumerations.MachineType GetArchitecture()
        {
            return _peHeaders.FileHeader.Machine;
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

                // Calculate the amount of relocations in the base relocation

                var relocationAmount = (baseRelocation.SizeOfBlock - Marshal.SizeOf<Structures.ImageBaseRelocation>()) / sizeof(ushort);

                var relocations = new List<Relocation>();

                for (var relocationIndex = 0; relocationIndex < relocationAmount; relocationIndex += 1)
                {
                    // Read the relocation

                    var relocation = Marshal.PtrToStructure<ushort>(_dllBuffer.AddOffset(relocationsOffset + (uint) (sizeof(ushort) * relocationIndex)));

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

        internal DebugData GetDebugData()
        {
            // Calculate the offset of the debug directory

            var debugDirectoryRva = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86
                                  ? _peHeaders.NtHeaders32.OptionalHeader.DataDirectory[6].VirtualAddress
                                  : _peHeaders.NtHeaders64.OptionalHeader.DataDirectory[6].VirtualAddress;

            if (debugDirectoryRva == 0)
            {
                // The DLL has no debug directory

                return default;
            }

            var debugDirectoryOffset = ConvertRvaToOffset(debugDirectoryRva);

            // Read the debug directory

            var debugDirectory = Marshal.PtrToStructure<Structures.ImageDebugDirectory>(_dllBuffer.AddOffset(debugDirectoryOffset));
            
            // Read the debug data

            var debugDataOffset = ConvertRvaToOffset(debugDirectory.AddressOfRawData);
            
            var debugData = Marshal.PtrToStructure<Structures.ImageDebugData>(_dllBuffer.AddOffset(debugDataOffset));
            
            // Read the name of the PDB
            
            var pdbName = Marshal.PtrToStringAnsi(_dllBuffer.AddOffset(debugDataOffset + (uint) Marshal.SizeOf<Structures.ImageDebugData>()));

            return new DebugData(debugData.Age, debugData.Guid.ToString().Replace("-", ""), pdbName);
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

            // Calculate the offset of the exported function offsets

            var exportedFunctionOffsetsOffset = ConvertRvaToOffset(exportDirectory.AddressOfFunctions);

            for (var functionIndex = 0; functionIndex < exportDirectory.NumberOfFunctions; functionIndex += 1)
            {
                // Read the offset of the exported function

                var exportedFunctionOffset = Marshal.PtrToStructure<uint>(_dllBuffer.AddOffset(exportedFunctionOffsetsOffset + (uint) (sizeof(uint) * functionIndex)));

                exportedFunctions.Add(new ExportedFunction(null, exportedFunctionOffset, (ushort) (exportDirectory.Base + functionIndex)));
            }

            // Calculate the offset of the exported function names

            var exportedFunctionNamesOffset = ConvertRvaToOffset(exportDirectory.AddressOfNames);

            // Calculate the offset of the exported function ordinals

            var exportedFunctionOrdinalsOffset = ConvertRvaToOffset(exportDirectory.AddressOfNameOrdinals);

            for (var exportedFunctionIndex = 0; exportedFunctionIndex < exportDirectory.NumberOfNames; exportedFunctionIndex += 1)
            {
                // Calculate the offset of the name of the exported function

                var exportedFunctionNameRva = Marshal.PtrToStructure<uint>(_dllBuffer.AddOffset(exportedFunctionNamesOffset + (uint) (sizeof(uint) * exportedFunctionIndex)));

                var exportedFunctionNameOffset = ConvertRvaToOffset(exportedFunctionNameRva);

                // Read the name of the exported function

                var exportedFunctionName = Marshal.PtrToStringAnsi(_dllBuffer.AddOffset(exportedFunctionNameOffset));

                // Read the ordinal of the exported function

                var exportedFunctionOrdinal = exportDirectory.Base + Marshal.PtrToStructure<ushort>(_dllBuffer.AddOffset(exportedFunctionOrdinalsOffset + (uint) (sizeof(ushort) * exportedFunctionIndex)));

                exportedFunctions.Find(exportedFunction => exportedFunction.Ordinal == exportedFunctionOrdinal).Name = exportedFunctionName;
            }

            return exportedFunctions;
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

                if (importDescriptor.FirstThunk == 0)
                {
                    break;
                }

                // Read the name of the import descriptor

                var importDescriptorNameOffset = ConvertRvaToOffset(importDescriptor.Name);

                var importDescriptorName = Marshal.PtrToStringAnsi(_dllBuffer.AddOffset(importDescriptorNameOffset));

                // Calculate the offset of the first imported function thunk

                var thunkOffset = importDescriptor.OriginalFirstThunk == 0
                                ? ConvertRvaToOffset(importDescriptor.FirstThunk)
                                : ConvertRvaToOffset(importDescriptor.OriginalFirstThunk);

                var firstThunkOffset = ConvertRvaToOffset(importDescriptor.FirstThunk);

                while (true)
                {
                    if (_peHeaders.FileHeader.Machine == Enumerations.MachineType.X86)
                    {
                        // Read the thunk of the imported function

                        var importedFunctionThunk = Marshal.PtrToStructure<uint>(_dllBuffer.AddOffset(thunkOffset));

                        if (importedFunctionThunk == 0)
                        {
                            break;
                        }

                        // Check if the function is imported by its ordinal

                        if ((importedFunctionThunk & Constants.OrdinalFlag32) == Constants.OrdinalFlag32)
                        {
                            importedFunctions.Add(new ImportedFunction(importDescriptorName, firstThunkOffset, (ushort) (importedFunctionThunk & 0xFFFF)));
                        }

                        else
                        {
                            // Read the ordinal of the imported function

                            var importedFunctionOrdinalOffset = ConvertRvaToOffset(importedFunctionThunk);

                            var importedFunctionOrdinal = Marshal.PtrToStructure<ushort>(_dllBuffer.AddOffset(importedFunctionOrdinalOffset));

                            // Read the name of the imported function

                            var importedFunctionName = Marshal.PtrToStringAnsi(_dllBuffer.AddOffset(importedFunctionOrdinalOffset + sizeof(ushort)));

                            importedFunctions.Add(new ImportedFunction(importDescriptorName, importedFunctionName, firstThunkOffset, importedFunctionOrdinal));
                        }

                        thunkOffset += sizeof(uint);

                        firstThunkOffset += sizeof(uint);
                    }

                    else
                    {
                        // Read the thunk of the imported function

                        var importedFunctionThunk = Marshal.PtrToStructure<ulong>(_dllBuffer.AddOffset(thunkOffset));

                        if (importedFunctionThunk == 0)
                        {
                            break;
                        }

                        // Check if the function is imported by its ordinal

                        if ((importedFunctionThunk & Constants.OrdinalFlag64) == Constants.OrdinalFlag64)
                        {
                            importedFunctions.Add(new ImportedFunction(importDescriptorName, firstThunkOffset, (ushort) (importedFunctionThunk & 0xFFFF)));
                        }

                        else
                        {
                            // Read the name of the imported function

                            var importedFunctionNameOffset = ConvertRvaToOffset(importedFunctionThunk) + sizeof(ushort);

                            var importedFunctionName = Marshal.PtrToStringAnsi(_dllBuffer.AddOffset(importedFunctionNameOffset));

                            importedFunctions.Add(new ImportedFunction(importDescriptorName, importedFunctionName, firstThunkOffset));
                        }

                        thunkOffset += sizeof(ulong);

                        firstThunkOffset += sizeof(ulong);
                    }
                }

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
                // The DLL has no TLS directory

                yield break;
            }

            var tlsDirectoryOffset = ConvertRvaToOffset(tlsDirectoryRva);

            if (_peHeaders.FileHeader.Machine == Enumerations.MachineType.X86)
            {
                // Read the TLS directory

                var tlsDirectory = Marshal.PtrToStructure<Structures.ImageTlsDirectory32>(_dllBuffer.AddOffset(tlsDirectoryOffset));

                if (tlsDirectory.AddressOfCallbacks == 0)
                {
                    // The DLL has no TLS callbacks

                    yield break;
                }

                // Calculate the offset of the TLS callbacks

                var tlsCallbacksOffset = ConvertRvaToOffset(tlsDirectory.AddressOfCallbacks - _peHeaders.NtHeaders32.OptionalHeader.ImageBase);

                while (true)
                {
                    // Read the TLS callback RVA

                    var tlsCallbackRva = Marshal.PtrToStructure<uint>(_dllBuffer.AddOffset(tlsCallbacksOffset));

                    if (tlsCallbackRva == 0)
                    {
                        break;
                    }

                    // Calculate the offset of the TLS callback

                    var tlsCallbackOffset = ConvertRvaToOffset(tlsCallbackRva - _peHeaders.NtHeaders32.OptionalHeader.ImageBase);

                    yield return new TlsCallback(tlsCallbackOffset);

                    // Calculate the offset of the next TLS callback RVA

                    tlsCallbacksOffset += sizeof(uint);
                }
            }

            else
            {
                // Read the TLS directory

                var tlsDirectory = Marshal.PtrToStructure<Structures.ImageTlsDirectory64>(_dllBuffer.AddOffset(tlsDirectoryOffset));

                if (tlsDirectory.AddressOfCallbacks == 0)
                {
                    // The DLL has no TLS callbacks

                    yield break;
                }

                // Calculate the offset of the TLS callbacks

                var tlsCallbacksOffset = ConvertRvaToOffset(tlsDirectory.AddressOfCallbacks - _peHeaders.NtHeaders64.OptionalHeader.ImageBase);

                while (true)
                {
                    // Read the TLS callback RVA

                    var tlsCallbackRva = Marshal.PtrToStructure<ulong>(_dllBuffer.AddOffset(tlsCallbacksOffset));

                    if (tlsCallbackRva == 0)
                    {
                        break;
                    }

                    // Calculate the offset of the TLS callback

                    var tlsCallbackOffset = ConvertRvaToOffset(tlsCallbackRva - _peHeaders.NtHeaders64.OptionalHeader.ImageBase);

                    yield return new TlsCallback(tlsCallbackOffset);

                    // Calculate the offset of the next TLS callback RVA

                    tlsCallbacksOffset += sizeof(ulong);
                }
            }
        }

        internal PeHeaders GetPeHeaders()
        {
            return _peHeaders;
        }

        private ulong ConvertRvaToOffset(ulong rva)
        {
            // Look for the section that holds the offset of the relative virtual address

            var sectionHeader = _peHeaders.SectionHeaders.Find(section => section.VirtualAddress <= rva && section.VirtualAddress + section.VirtualSize > rva);

            // Calculate the offset of the relative virtual address

            return sectionHeader.PointerToRawData + (rva - sectionHeader.VirtualAddress);
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

            if (_peHeaders.FileHeader.Machine == Enumerations.MachineType.X86)
            {
                _peHeaders.NtHeaders32 = Marshal.PtrToStructure<Structures.ImageNtHeaders32>(_dllBuffer.AddOffset(_peHeaders.DosHeader.e_lfanew));

                if (_peHeaders.NtHeaders32.Signature != Constants.NtSignature)
                {
                    throw new BadImageFormatException("The NT headers of the DLL were invalid");
                }

                if (_peHeaders.NtHeaders32.OptionalHeader.DataDirectory[14].VirtualAddress != 0)
                {
                    throw new BadImageFormatException(".Net DLLs are not supported");
                }
            }

            else
            {
                _peHeaders.NtHeaders64 = Marshal.PtrToStructure<Structures.ImageNtHeaders64>(_dllBuffer.AddOffset(_peHeaders.DosHeader.e_lfanew));

                if (_peHeaders.NtHeaders64.Signature != Constants.NtSignature)
                {
                    throw new BadImageFormatException("The NT headers of the DLL were invalid");
                }

                if (_peHeaders.NtHeaders64.OptionalHeader.DataDirectory[14].VirtualAddress != 0)
                {
                    throw new BadImageFormatException(".Net DLLs are not supported");
                }
            }

            // Read the section headers

            var sectionHeadersOffset = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86
                                     ? _peHeaders.DosHeader.e_lfanew + Marshal.SizeOf<Structures.ImageNtHeaders32>()
                                     : _peHeaders.DosHeader.e_lfanew + Marshal.SizeOf<Structures.ImageNtHeaders64>();

            for (var sectionHeaderIndex = 0; sectionHeaderIndex < _peHeaders.FileHeader.NumberOfSections; sectionHeaderIndex += 1)
            {
                var sectionHeader = Marshal.PtrToStructure<Structures.ImageSectionHeader>(_dllBuffer.AddOffset(sectionHeadersOffset + Marshal.SizeOf<Structures.ImageSectionHeader>() * sectionHeaderIndex));

                _peHeaders.SectionHeaders.Add(sectionHeader);
            }
        }
    }
}