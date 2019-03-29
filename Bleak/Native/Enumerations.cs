using System;

namespace Bleak.Native
{
    internal static class Enumerations
    {
        internal enum ContextFlags
        {
            Control = 0x10001
        }

        [Flags]
        internal enum SectionCharacteristics : uint
        {
            MemoryNotCached = 0x04000000,
            MemoryExecute = 0x020000000,
            MemoryRead = 0x040000000,
            MemoryWrite = 0x080000000
        }

        internal enum FileCharacteristics : ushort
        {
            RelocationsStripped = 0x01,
            Dll = 0x2000
        }

        internal enum MachineType : ushort
        {
            X86 = 0x14C,
            X64 = 0x8664
        }

        [Flags]
        internal enum MemoryAllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000
        }

        [Flags]
        internal enum MemoryFreeType
        {
            Release = 0x8000
        }

        internal enum MemoryInformationClass
        {
            BasicInformation = 0x00
        }

        [Flags]
        internal enum MemoryProtectionType
        {
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            Guard = 0x100,
            NoCache = 0x200,
            WriteCombine = 0x400
        }

        internal enum NtStatus : uint
        {
            Success = 0x00
        }

        [Flags]
        internal enum ProcessAccessMask
        {
            SpecificRightsAll = 0xFFFF,
            StandardRightsAll = 0x1F0000,
            AllAccess = SpecificRightsAll | StandardRightsAll
        }

        internal enum ProcessInformationClass
        {
            BasicInformation = 0x00,
            Wow64Information = 0x1A
        }

        internal enum RelocationType : byte
        {
            HighLow = 0x03,
            Dir64 = 0x0A
        }

        [Flags]
        internal enum ThreadAccessMask
        {
            SpecificRightsAll = 0xFFFF,
            StandardRightsAll = 0x1F0000,
            AllAccess = SpecificRightsAll | StandardRightsAll
        }

        internal enum ThreadCreationType
        {
            HideFromDebugger = 0x04
        }
    }
}
