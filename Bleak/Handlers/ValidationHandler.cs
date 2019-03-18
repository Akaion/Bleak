using Bleak.Native;
using Bleak.Wrappers;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Handlers
{
    internal static class ValidationHandler
    {
        internal static void ValidateDllArchitecture(PropertyWrapper propertyWrapper)
        {
            // Ensure the architecture of the target process matches the architecture of the DLL

            if (propertyWrapper.IsWow64Process.Value != (propertyWrapper.PeParser.GetPeArchitecture() == Enumerations.MachineType.X86))
            {
                throw new ApplicationException("The architecture of the target process did not match the architecture of the DLL");
            }

            // Ensure that x64 injection is not being attempted from an x86 process

            if (!propertyWrapper.IsWow64Process.Value && !Environment.Is64BitProcess)
            {
                throw new ApplicationException("You cannot inject into an x64 when compiled under x86");
            }
        }

        internal static void ValidateOperatingSystem()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                throw new PlatformNotSupportedException("This library is intended for Windows NT use only and will not work on Linux");
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                throw new PlatformNotSupportedException("This library is intended for Windows NT use only and will not work on OSX");
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new PlatformNotSupportedException("This library is intended for Windows NT use only and will not work on earlier versions of Windows");
            }

            if (!Environment.Is64BitOperatingSystem)
            {
                throw new PlatformNotSupportedException("This library is intended for 64 bit operating systems only and will not work on 32 bit operating systems");
            }
        }
    }
}
