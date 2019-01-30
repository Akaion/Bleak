using System;
using System.Runtime.InteropServices;

namespace Bleak.Services
{
    internal static class ValidateOperatingSystem
    {
        internal static void Validate()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                throw new PlatformNotSupportedException("This library is intended for Windows use only and will not work on Linux");
            }
            
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                throw new PlatformNotSupportedException("This library is intended for Windows use only and will not work on OSX");
            }
        }
    }
}