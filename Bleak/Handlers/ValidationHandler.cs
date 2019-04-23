using Bleak.Injection.Objects;
using Bleak.Native;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Handlers
{
    internal static class ValidationHandler
    {
        internal static void ValidateDllArchitecture(InjectionProperties injectionProperties)
        {
            // Ensure the architecture of the target process matches the architecture of the DLL

            if (injectionProperties.RemoteProcess.IsWow64 != (injectionProperties.PeParser.GetArchitecture() == Enumerations.MachineType.X86))
            {
                throw new ApplicationException("The architecture of the target process did not match the architecture of the DLL");
            }

            // Ensure that x64 injection is not being attempted from an x86 build

            if (!Environment.Is64BitProcess && !injectionProperties.RemoteProcess.IsWow64)
            {
                throw new ApplicationException("x64 injection is not supported when compiled under x86");
            }
        }

        internal static void ValidateOperatingSystem()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                throw new PlatformNotSupportedException("This library is intended for Windows use only and will not work on Linux");
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                throw new PlatformNotSupportedException("This library is intended for Windows use only and will not work on OSX");
            }

            if (!Environment.Is64BitOperatingSystem)
            {
                throw new PlatformNotSupportedException("This library is intended for 64 bit Windows use only and will not work on 32 bit versions of Windows");
            }
        }
    }
}
