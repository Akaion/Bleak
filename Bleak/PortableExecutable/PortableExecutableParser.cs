using Bleak.Native;
using Bleak.PortableExecutable.Objects;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Bleak.PortableExecutable
{
    internal class PortableExecutableParser : IDisposable
    {
        private readonly GCHandle _dllBuffer;

        private readonly IntPtr _dllBufferAddress;

        private readonly PeHeaders _peHeaders;

        internal PortableExecutableParser(byte[] dllBytes)
        {
            _dllBuffer = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);

            _dllBufferAddress = _dllBuffer.AddrOfPinnedObject();

            _peHeaders = new PeHeaders();

            ReadHeaders();
        }

        internal PortableExecutableParser(string dllPath)
        {
            _dllBuffer = GCHandle.Alloc(File.ReadAllBytes(dllPath), GCHandleType.Pinned);

            _dllBufferAddress = _dllBuffer.AddrOfPinnedObject();

            _peHeaders = new PeHeaders();

            ReadHeaders();
        }

        public void Dispose()
        {
            _dllBuffer.Free();
        }

        private IntPtr AddOffsetToPointer(IntPtr pointer, ulong offset)
        {
            return (IntPtr) ((ulong) pointer + offset);
        }

        private ulong ConvertRvaToFileOffset(ulong rva)
        {
            // Look for the section header that holds the offset of the relative virtual address

            var sectionHeader = _peHeaders.SectionHeaders.Find(section => section.VirtualAddress <= rva && section.VirtualAddress + section.VirtualSize > rva);

            // Calculate the offset of the relative virtual address

            return sectionHeader.PointerToRawData + (rva - sectionHeader.VirtualAddress);
        }

        internal List<BaseRelocation> GetBaseRelocations()
        {
            var baseRelocations = new List<BaseRelocation>();

            // Calculate the offset of the base relocation table

            var baseRelocationTableRva = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? _peHeaders.NtHeaders32.OptionalHeader.DataDirectory[5].VirtualAddress : _peHeaders.NtHeaders64.OptionalHeader.DataDirectory[5].VirtualAddress;

            if (baseRelocationTableRva == 0)
            {
                return default;
            }

            var baseRelocationTableOffset = ConvertRvaToFileOffset(baseRelocationTableRva);

            while (true)
            {
                // Read the base relocation

                var baseRelocation = Marshal.PtrToStructure<Structures.ImageBaseRelocation>(AddOffsetToPointer(_dllBufferAddress, baseRelocationTableOffset));

                if (baseRelocation.SizeOfBlock == 0)
                {
                    break;
                }

                // Calculate the amount of type offsets in the base relocation

                var typeOffsetAmount = (baseRelocation.SizeOfBlock - 8) / sizeof(ushort);

                // Calculate the offset of the type offsets

                var typeOffsetsOffset = baseRelocationTableOffset + (uint) Marshal.SizeOf<Structures.ImageBaseRelocation>();

                var typeOffsets = new List<TypeOffset>();

                for (var index = 0; index < typeOffsetAmount; index += 1)
                {
                    // Read the type offset

                    var typeOffset = Marshal.PtrToStructure<ushort>(AddOffsetToPointer(_dllBufferAddress, typeOffsetsOffset + (uint) (sizeof(ushort) * index)));

                    // The offset is located in the upper 4 bits of the ushort

                    var offset = typeOffset & 0xFFF;

                    // The type is located in the lower 12 bits of the ushort

                    var type = typeOffset >> 12;

                    typeOffsets.Add(new TypeOffset((ushort) offset, (Enumerations.RelocationType) type));
                }

                baseRelocations.Add(new BaseRelocation(ConvertRvaToFileOffset(baseRelocation.VirtualAddress), typeOffsets));

                // Calculate the offset of the next base relocation

                baseRelocationTableOffset += baseRelocation.SizeOfBlock;
            }

            return baseRelocations;
        }

        internal Enumerations.MachineType GetPeArchitecture()
        {
            return _peHeaders.FileHeader.Machine;
        }

        internal List<ExportedFunction> GetExportedFunctions()
        {
            var exportedFunctions = new List<ExportedFunction>();

            // Calculate the offset of the export directory            

            var exportDirectoryRva = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? _peHeaders.NtHeaders32.OptionalHeader.DataDirectory[0].VirtualAddress : _peHeaders.NtHeaders64.OptionalHeader.DataDirectory[0].VirtualAddress;

            if (exportDirectoryRva == 0)
            {
                // The portable executable has no export directory

                return exportedFunctions;
            }

            var exportDirectoryOffset = ConvertRvaToFileOffset(exportDirectoryRva);

            // Read the export directory

            var exportDirectory = Marshal.PtrToStructure<Structures.ImageExportDirectory>(AddOffsetToPointer(_dllBufferAddress, exportDirectoryOffset));

            // Calculate the offset of the exported function offsets

            var exportedFunctionOffsetsOffset = ConvertRvaToFileOffset(exportDirectory.AddressOfFunctions);

            for (var index = 0; index < exportDirectory.NumberOfFunctions; index += 1)
            {
                // Read the offset of the exported function

                var exportedFunctionOffset = Marshal.PtrToStructure<uint>(AddOffsetToPointer(_dllBufferAddress, exportedFunctionOffsetsOffset + (uint) (sizeof(uint) * index)));

                // Calculate the ordinal of the exported function

                var exportedFunctionOrdinal = exportDirectory.Base + index;

                exportedFunctions.Add(new ExportedFunction(null, exportedFunctionOffset, (ushort) exportedFunctionOrdinal));
            }

            // Calculate the offset of the exported function names

            var exportedFunctionNamesOffset = ConvertRvaToFileOffset(exportDirectory.AddressOfNames);

            // Calculate the offset of the exported function ordinals

            var exportedFunctionOrdinalsOffset = ConvertRvaToFileOffset(exportDirectory.AddressOfNameOrdinals);

            for (var index = 0; index < exportDirectory.NumberOfNames; index += 1)
            {
                // Read the name of the exported function

                var exportedFunctionNameRva = Marshal.PtrToStructure<uint>(AddOffsetToPointer(_dllBufferAddress, exportedFunctionNamesOffset + (uint) (sizeof(uint) * index)));

                var exportedFunctionNameOffset = ConvertRvaToFileOffset(exportedFunctionNameRva);

                var exportedFunctionName = Marshal.PtrToStringAnsi(AddOffsetToPointer(_dllBufferAddress, exportedFunctionNameOffset));

                // Read the ordinal of the exported function

                var exportedFunctionOrdinal = exportDirectory.Base + Marshal.PtrToStructure<ushort>(AddOffsetToPointer(_dllBufferAddress, exportedFunctionOrdinalsOffset + (uint) (sizeof(ushort) * index)));

                // Associate the name of the exported function with the exported function

                exportedFunctions.Find(exportedFunction => exportedFunction.Ordinal == exportedFunctionOrdinal).Name = exportedFunctionName;
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

            var importDescriptorRva = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? _peHeaders.NtHeaders32.OptionalHeader.DataDirectory[1].VirtualAddress : _peHeaders.NtHeaders64.OptionalHeader.DataDirectory[1].VirtualAddress;

            if (importDescriptorRva == 0)
            {
                // The portable executable has no import descriptors

                return importedFunctions;
            }

            var importDescriptorOffset = ConvertRvaToFileOffset(importDescriptorRva);

            while (true)
            {
                // Read the import descriptor

                var importDescriptor = Marshal.PtrToStructure<Structures.ImageImportDescriptor>(_dllBufferAddress + (int) importDescriptorOffset);

                if (importDescriptor.OriginalFirstThunk == 0)
                {
                    break;
                }

                // Read the name of the imported dll

                var importedDllNameOffset = ConvertRvaToFileOffset(importDescriptor.Name);

                var importedDllName = Marshal.PtrToStringAnsi(_dllBufferAddress + (int) importedDllNameOffset);

                // Calculate the offsets of original first thunk and first thunk of the import descriptor

                var originalFirstThunkOffset = ConvertRvaToFileOffset(importDescriptor.OriginalFirstThunk);

                var firstThunkOffset = ConvertRvaToFileOffset(importDescriptor.FirstThunk);

                while (true)
                {
                    // Read the thunk data of the imported function

                    var importedFunctionThunkData = Marshal.PtrToStructure<Structures.ImageThunkData>(_dllBufferAddress + (int) originalFirstThunkOffset);

                    if (importedFunctionThunkData.AddressOfData == 0)
                    {
                        break;
                    }

                    // Read the name of the imported function

                    var importedFunctionOffset = ConvertRvaToFileOffset(importedFunctionThunkData.AddressOfData);

                    var importedFunctionName = Marshal.PtrToStringAnsi(_dllBufferAddress + (int) importedFunctionOffset + sizeof(ushort));

                    importedFunctions.Add(new ImportedFunction(importedDllName, importedFunctionName, firstThunkOffset));
                    
                    // Calculate the offset of the original first thunk of the next imported function

                    originalFirstThunkOffset += _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? (uint) sizeof(uint) : sizeof(ulong);

                    // Calculate the offset of the first thunk of the next imported function

                    firstThunkOffset += _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? (uint) sizeof(uint) : sizeof(ulong);
                }

                // Calculate the offset of the next import descriptor

                importDescriptorOffset += (uint) Marshal.SizeOf<Structures.ImageImportDescriptor>();
            }

            return importedFunctions;
        }

        internal List<TlsCallback> GetTlsCallbacks()
        {
            var tlsCallbacks = new List<TlsCallback>();

            switch (_peHeaders.FileHeader.Machine)
            {
                case Enumerations.MachineType.X86:
                {
                    if (_peHeaders.NtHeaders32.OptionalHeader.DataDirectory[9].VirtualAddress == 0)
                    {
                        return tlsCallbacks;
                    }

                    // Read the TLS directory

                    var tlsDirectoryOffset = ConvertRvaToFileOffset(_peHeaders.NtHeaders32.OptionalHeader.DataDirectory[9].VirtualAddress);
                    
                    var tlsDirectory = Marshal.PtrToStructure<Structures.ImageTlsDirectory32>(AddOffsetToPointer(_dllBufferAddress, tlsDirectoryOffset));
                    
                    // Calculate the offset of the TLS callbacks

                    var tlsCallbacksOffset = ConvertRvaToFileOffset(tlsDirectory.AddressOfCallbacks - _peHeaders.NtHeaders64.OptionalHeader.ImageBase);
                    
                    while (true)
                    {
                        // Read the TLS callback

                        var tlsCallback = Marshal.PtrToStructure<uint>(AddOffsetToPointer(_dllBufferAddress, tlsCallbacksOffset));
                        
                        if (tlsCallback == 0)
                        {
                            break;
                        }

                        // Calculate the offset of the TLS callback

                        var tlsCallbackOffset = ConvertRvaToFileOffset(tlsCallback - _peHeaders.NtHeaders64.OptionalHeader.ImageBase);
                        
                        tlsCallbacks.Add(new TlsCallback(tlsCallbackOffset));
                        
                        // Calculate the offset of the next TLS callback

                        tlsCallbacksOffset += sizeof(uint);
                    }

                    break;
                }
                
                case Enumerations.MachineType.X64:
                {
                    if (_peHeaders.NtHeaders64.OptionalHeader.DataDirectory[9].VirtualAddress == 0)
                    {
                        return tlsCallbacks;
                    }

                    // Read the TLS directory

                    var tlsDirectoryOffset = ConvertRvaToFileOffset(_peHeaders.NtHeaders64.OptionalHeader.DataDirectory[9].VirtualAddress);

                    var tlsDirectory = Marshal.PtrToStructure<Structures.ImageTlsDirectory64>(AddOffsetToPointer(_dllBufferAddress, tlsDirectoryOffset));
                    
                    // Calculate the offset of the TLS callbacks

                    var tlsCallbacksOffset = ConvertRvaToFileOffset(tlsDirectory.AddressOfCallbacks - _peHeaders.NtHeaders64.OptionalHeader.ImageBase);
                    
                    while (true)
                    {
                        // Read the TLS callback

                        var tlsCallback = Marshal.PtrToStructure<ulong>(AddOffsetToPointer(_dllBufferAddress, tlsCallbacksOffset));
                        
                        if (tlsCallback == 0)
                        {
                            break;
                        }

                        // Calculate the offset of the TLS callback

                        var tlsCallbackOffset = ConvertRvaToFileOffset(tlsCallback - _peHeaders.NtHeaders64.OptionalHeader.ImageBase);
                        
                        tlsCallbacks.Add(new TlsCallback(tlsCallbackOffset));
                        
                        // Calculate the offset of the next TLS callback

                        tlsCallbacksOffset += sizeof(ulong);
                    }

                    break;
                }
            }

            return tlsCallbacks;
        }

        private void ReadHeaders()
        {
            // Read the DOS header

            _peHeaders.DosHeader = Marshal.PtrToStructure<Structures.ImageDosHeader>(_dllBufferAddress);

            if (_peHeaders.DosHeader.e_magic != 0x5A4D)
            {
                throw new BadImageFormatException("The headers of the provided DLL were invalid");
            }

            // Read the file header

            _peHeaders.FileHeader = Marshal.PtrToStructure<Structures.ImageFileHeader>(_dllBufferAddress + _peHeaders.DosHeader.e_lfanew + sizeof(uint));

            if ((_peHeaders.FileHeader.Characteristics & (ushort) Enumerations.FileCharacteristics.Dll) == 0)
            {
                throw new BadImageFormatException("The headers of the provided DLL were invalid");
            }

            // Read the NT headers

            switch (_peHeaders.FileHeader.Machine)
            {
                case Enumerations.MachineType.X86:
                {
                    _peHeaders.NtHeaders32 = Marshal.PtrToStructure<Structures.ImageNtHeaders32>(_dllBufferAddress + _peHeaders.DosHeader.e_lfanew);
                    
                    if (_peHeaders.NtHeaders32.Signature != 0x4550)
                    {
                        throw new BadImageFormatException("The headers of the provided DLL were invalid");
                    }

                    if (_peHeaders.NtHeaders32.OptionalHeader.DataDirectory[14].VirtualAddress != 0)
                    {
                        throw new BadImageFormatException(".Net DLL's are not supported in this library");
                    }

                    break;
                }
                
                case Enumerations.MachineType.X64:
                {
                    _peHeaders.NtHeaders64 = Marshal.PtrToStructure<Structures.ImageNtHeaders64>(_dllBufferAddress + _peHeaders.DosHeader.e_lfanew);
                    
                    if (_peHeaders.NtHeaders64.Signature != 0x4550)
                    {
                        throw new BadImageFormatException("The headers of the provided DLL were invalid");
                    }

                    if (_peHeaders.NtHeaders64.OptionalHeader.DataDirectory[14].VirtualAddress != 0)
                    {
                        throw new BadImageFormatException(".Net DLL's are not supported in this library");
                    }

                    break;
                }
                
                default:
                {
                    throw new BadImageFormatException("The architecture of the provided DLL was invalid");
                }
            }
            
            // Read the section headers

            var sectionHeadersOffset = _peHeaders.FileHeader.Machine == Enumerations.MachineType.X86 ? _peHeaders.DosHeader.e_lfanew + Marshal.SizeOf<Structures.ImageNtHeaders32>() : _peHeaders.DosHeader.e_lfanew + Marshal.SizeOf<Structures.ImageNtHeaders64>();

            for (var index = 0; index < _peHeaders.FileHeader.NumberOfSections; index += 1)
            {
                _peHeaders.SectionHeaders.Add(Marshal.PtrToStructure<Structures.ImageSectionHeader>(_dllBufferAddress + sectionHeadersOffset + Marshal.SizeOf<Structures.ImageSectionHeader>() * index));
            }
        }
    }
}
