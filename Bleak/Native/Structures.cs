using System;
using System.Runtime.InteropServices;

namespace Bleak.Native
{
    internal static class Structures
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct ClientId
        {
            internal IntPtr UniqueProcess;

            internal IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct Context
        {
            private readonly ulong P1Home;
            private readonly ulong P2Home;
            private readonly ulong P3Home;
            private readonly ulong P4Home;
            private readonly ulong P5Home;
            private readonly ulong P6Home;

            internal Enumerations.ContextFlags ContextFlags;

            private readonly uint MxCsr;

            private readonly ushort SegCs;
            private readonly ushort SegDs;
            private readonly ushort SegEs;
            private readonly ushort SegFs;
            private readonly ushort SegGs;
            private readonly ushort SegSs;

            private readonly uint EFlags;

            private readonly ulong Dr0;
            private readonly ulong Dr1;
            private readonly ulong Dr2;
            private readonly ulong Dr3;
            private readonly ulong Dr6;
            private readonly ulong Dr7;

            private readonly ulong Rax;
            private readonly ulong Rcx;
            private readonly ulong Rdx;
            private readonly ulong Rbx;
            private readonly ulong Rsp;
            private readonly ulong Rbp;
            private readonly ulong Rsi;
            private readonly ulong Rdi;
            private readonly ulong R8;
            private readonly ulong R9;
            private readonly ulong R10;
            private readonly ulong R11;
            private readonly ulong R12;
            private readonly ulong R13;
            private readonly ulong R14;
            private readonly ulong R15;

            internal ulong Rip;

            private readonly SaveFormat DummyUnionName;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            private readonly M128A[] VectorRegister;

            private readonly ulong VectorControl;
            private readonly ulong DebugControl;

            private readonly ulong LastBranchToRip;
            private readonly ulong LastBranchFromRip;
            private readonly ulong LastExceptionToRip;
            private readonly ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageBaseRelocation
        {
            internal readonly uint VirtualAddress;

            internal readonly uint SizeOfBlock;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageDataDirectory
        {
            internal readonly uint VirtualAddress;

            internal readonly uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageDosHeader
        {
            internal readonly ushort e_magic;

            private readonly ushort e_cblp;

            private readonly ushort e_cp;

            private readonly ushort e_crlc;

            private readonly ushort e_cparhdr;

            private readonly ushort e_minalloc;
            private readonly ushort e_maxalloc;

            private readonly ushort e_ss;

            private readonly ushort e_sp;

            private readonly ushort e_csum;

            private readonly ushort e_ip;

            private readonly ushort e_cs;

            private readonly ushort e_lfarlc;

            private readonly ushort e_ovno;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            private readonly ushort[] e_res;

            private readonly ushort e_oemid;
            private readonly ushort e_oeminfo;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            private readonly ushort[] e_res2;

            internal readonly ushort e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageExportDirectory
        {
            private readonly uint Characteristics;

            private readonly uint TimeDateStamp;

            private readonly ushort MajorVersion;
            private readonly ushort MinorVersion;

            private readonly uint Name;

            internal readonly uint Base;

            internal readonly uint NumberOfFunctions;
            internal readonly uint NumberOfNames;

            internal readonly uint AddressOfFunctions;
            internal readonly uint AddressOfNames;
            internal readonly uint AddressOfNameOrdinals;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageFileHeader
        {
            internal readonly Enumerations.MachineType Machine;

            internal readonly ushort NumberOfSections;

            private readonly uint TimeDateStamp;

            private readonly uint PointerToSymbolTable;
            private readonly uint NumberOfSymbols;

            private readonly ushort SizeOfOptionalHeader;

            internal readonly ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageImportDescriptor
        {
            internal readonly uint OriginalFirstThunk;

            private readonly uint TimeDateStamp;

            private readonly uint ForwarderChain;

            internal readonly uint Name;

            internal readonly uint FirstThunk;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageNtHeaders32
        {
            internal readonly uint Signature;

            private readonly ImageFileHeader FileHeader;

            internal readonly ImageOptionalHeader32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageNtHeaders64
        {
            internal readonly uint Signature;

            private readonly ImageFileHeader FileHeader;

            internal readonly ImageOptionalHeader64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageOptionalHeader32
        {
            private readonly ushort Magic;

            private readonly byte MajorLinkerVersion;
            private readonly byte MinorLinkerVersion;

            private readonly uint SizeOfCode;
            private readonly uint SizeOfInitialisedData;
            private readonly uint SizeOfUnInitialisedData;

            internal readonly uint AddressOfEntryPoint;

            private readonly uint BaseOfCode;
            private readonly uint BaseOfData;

            internal readonly uint ImageBase;

            private readonly uint SectionAlignment;
            private readonly uint FileAlignment;

            private readonly ushort MajorOperatingSystemVersion;
            private readonly ushort MinorOperatingSystemVersion;

            private readonly ushort MajorImageVersion;
            private readonly ushort MinorImageVersion;

            private readonly ushort MajorSubsystemVersion;
            private readonly ushort MinorSubsystemVersion;

            private readonly uint Win32VersionValue;

            internal readonly uint SizeOfImage;

            private readonly uint SizeOfHeaders;

            private readonly uint CheckSum;

            private readonly ushort Subsystem;

            private readonly ushort DllCharacteristics;

            private readonly uint SizeOfStackReserve;
            private readonly uint SizeOfStackCommit;

            private readonly uint SizeOfHeapReserve;
            private readonly uint SizeOfHeapCommit;

            private readonly uint LoaderFlags;

            private readonly uint NumberOfRvaAndSizes;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            internal readonly ImageDataDirectory[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageOptionalHeader64
        {
            private readonly ushort Magic;

            private readonly byte MajorLinkerVersion;
            private readonly byte MinorLinkerVersion;

            private readonly uint SizeOfCode;
            private readonly uint SizeOfInitialisedData;
            private readonly uint SizeOfUnInitialisedData;

            internal readonly uint AddressOfEntryPoint;

            private readonly uint BaseOfCode;

            internal readonly ulong ImageBase;

            private readonly uint SectionAlignment;
            private readonly uint FileAlignment;

            private readonly ushort MajorOperatingSystemVersion;
            private readonly ushort MinorOperatingSystemVersion;

            private readonly ushort MajorImageVersion;
            private readonly ushort MinorImageVersion;

            private readonly ushort MajorSubsystemVersion;
            private readonly ushort MinorSubsystemVersion;

            private readonly uint Win32VersionValue;

            internal readonly uint SizeOfImage;

            private readonly uint SizeOfHeaders;

            private readonly uint CheckSum;

            private readonly ushort Subsystem;

            private readonly ushort DllCharacteristics;

            private readonly ulong SizeOfStackReserve;
            private readonly ulong SizeOfStackCommit;

            private readonly ulong SizeOfHeapReserve;
            private readonly ulong SizeOfHeapCommit;

            private readonly uint LoaderFlags;

            private readonly uint NumberOfRvaAndSizes;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            internal readonly ImageDataDirectory[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageSectionHeader
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            private readonly byte[] Name;

            internal readonly uint VirtualSize;
            internal readonly uint VirtualAddress;

            internal readonly uint SizeOfRawData;

            internal readonly uint PointerToRawData;
            private readonly uint PointerToRelocations;
            private readonly uint PointerToLineNumbers;

            private readonly ushort NumberOfRelocations;
            private readonly ushort NumberOfLineNumbers;

            internal readonly Enumerations.SectionCharacteristics Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct ImageThunkData
        {
            [FieldOffset(0)]
            private readonly uint ForwarderString;

            [FieldOffset(0)]
            private readonly uint Function;

            [FieldOffset(0)]
            private readonly uint Ordinal;

            [FieldOffset(0)]
            internal readonly uint AddressOfData;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageTlsDirectory32
        {
            private readonly uint StartAddressOfRawData;
            private readonly uint EndAddressOfRawData;

            private readonly uint AddressOfIndex;

            internal readonly uint AddressOfCallbacks;

            private readonly uint SizeOfZeroFill;

            private readonly uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ImageTlsDirectory64
        {
            private readonly ulong StartAddressOfRawData;
            private readonly ulong EndAddressOfRawData;

            private readonly ulong AddressOfIndex;

            internal readonly ulong AddressOfCallbacks;

            private readonly uint SizeOfZeroFill;

            private readonly uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LdrDataTableEntry32
        {
            internal readonly ListEntry32 InLoadOrderLinks;
            internal readonly ListEntry32 InMemoryOrderLinks;
            internal readonly ListEntry32 InInitOrderLinks;

            internal readonly uint DllBase;

            private readonly uint EntryPoint;

            private readonly uint SizeOfImage;

            internal UnicodeString32 FullDllName;

            internal UnicodeString32 BaseDllName;

            private readonly uint Flags;

            private readonly ushort LoadCount;

            private readonly ushort TlsIndex;

            internal readonly ListEntry32 HashTableEntry;

            private readonly ulong TimeDateStamp;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LdrDataTableEntry64
        {
            internal readonly ListEntry64 InLoadOrderLinks;
            internal readonly ListEntry64 InMemoryOrderLinks;
            internal readonly ListEntry64 InInitOrderLinks;

            internal readonly ulong DllBase;

            private readonly ulong EntryPoint;

            private readonly ulong SizeOfImage;

            internal UnicodeString64 FullDllName;

            internal UnicodeString64 BaseDllName;

            private readonly uint Flags;

            private readonly ushort LoadCount;

            private readonly ushort TlsIndex;

            internal readonly ListEntry64 HashTableEntry;

            private readonly ulong TimeDateStamp;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ListEntry32
        {
            internal uint Flink;

            internal uint Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ListEntry64
        {
            internal ulong Flink;

            internal ulong Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct M128A
        {
            private readonly ulong High;
            private readonly ulong Low;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MemoryBasicInformation
        {
            private readonly IntPtr BaseAddress;

            private readonly IntPtr AllocationBase;
            private readonly Enumerations.MemoryProtectionType AllocationProtect;

            internal readonly IntPtr RegionSize;

            private readonly uint State;
            private readonly Enumerations.MemoryProtectionType Protect;
            private readonly uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ObjectAttributes
        {
            private readonly ulong Length;

            private readonly IntPtr RootDirectory;

            private readonly IntPtr ObjectName;

            private readonly ulong Attributes;

            private readonly IntPtr SecurityDescriptor;

            private readonly IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Peb32
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            private readonly byte[] Reserved1;

            private readonly byte BeingDebugged;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            private readonly byte[] Reserved2;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            private readonly uint[] Reserved3;

            internal readonly uint Ldr;

            private readonly uint ProcessParameters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            private readonly uint[] Reserved4;

            private readonly uint AtlThunkSListPtr;

            private readonly uint Reserved5;
            private readonly ulong Reserved6;
            private readonly uint Reserved7;
            private readonly ulong Reserved8;

            private readonly ulong AtlThunkSListPtr32;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 45)]
            private readonly uint[] Reserved9;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            private readonly byte[] Reserved10;

            private readonly uint PostProcessInitRoutine;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
            private readonly byte[] Reserved11;

            private readonly uint Reserved12;

            private readonly ulong SessionId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Peb64
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            private readonly byte[] Reserved1;

            private readonly byte BeingDebugged;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 21)]
            private readonly byte[] Reserved2;

            internal readonly ulong Ldr;

            private readonly ulong ProcessParameters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 520)]
            private readonly byte[] Reserved3;

            private readonly ulong PostProcessInitRoutine;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 136)]
            private readonly byte[] Reserved4;

            private readonly ulong SessionId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PebLdrData32
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            private readonly byte[] Reserved1;

            private readonly uint Reserved2;

            internal readonly ListEntry32 InLoadOrderModuleList;

            private readonly ListEntry32 InMemoryOrderModuleList;
            private readonly ListEntry32 InInitOrderModuleList;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PebLdrData64
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            private readonly byte[] Reserved1;

            private readonly ulong Reserved2;

            internal readonly ListEntry64 InLoadOrderModuleList;

            private readonly ListEntry64 InMemoryOrderModuleList;
            private readonly ListEntry64 InInitOrderModuleList;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInformation
        {
            private readonly IntPtr ExitStatus;

            internal readonly IntPtr PebBaseAddress;

            private readonly IntPtr AffinityMask;

            private readonly IntPtr BasePriority;

            private readonly IntPtr UniqueProcessId;
            private readonly IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct SaveFormat
        {
            private readonly ushort ControlWord;
            private readonly ushort StatusWord;
            private readonly byte TagWord;

            private readonly byte Reserved;

            private readonly ushort ErrorOpcode;
            private readonly uint ErrorOffset;
            private readonly ushort ErrorSelector;

            private readonly ushort Reserved2;

            private readonly uint DataOffset;
            private readonly ushort DataSelector;

            private readonly ushort Reserved3;

            private readonly uint MxCsr;
            private readonly uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            private readonly M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            private readonly M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            private readonly byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UnicodeString32
        {
            internal readonly ushort Length;

            internal readonly ushort MaximumLength;

            internal readonly uint Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UnicodeString64
        {
            internal readonly ushort Length;

            internal readonly ushort MaximumLength;

            internal readonly ulong Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Wow64Context
        {
            internal Enumerations.ContextFlags ContextFlags;

            private readonly uint Dr0;
            private readonly uint Dr1;
            private readonly uint Dr2;
            private readonly uint Dr3;
            private readonly uint Dr6;
            private readonly uint Dr7;

            private readonly Wow64FloatingSaveArea FloatingSave;

            private readonly uint SegGs;
            private readonly uint SegFs;
            private readonly uint SegEs;
            private readonly uint SegDs;

            private readonly uint Edi;
            private readonly uint Esi;
            private readonly uint Ebx;
            private readonly uint Edx;
            private readonly uint Ecx;
            private readonly uint Eax;

            private readonly uint Ebp;

            internal uint Eip;

            private readonly uint SegCs;

            private readonly uint EFlags;

            private readonly uint Esp;

            private readonly uint SegSs;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            private readonly byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Wow64FloatingSaveArea
        {
            private readonly uint ControlWord;
            private readonly uint StatusWord;
            private readonly uint TagWord;

            private readonly uint ErrorOffset;
            private readonly uint ErrorSelector;

            private readonly uint DataOffset;
            private readonly uint DataSelector;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            private readonly byte[] RegisterArea;

            private readonly uint Cr0NpxState;
        }
    }
}
