using System;
using System.Diagnostics;
using Bleak.Etc;
using PeNet;

namespace Bleak.Services
{
    internal static class ValidateArchitecture
    {
        internal static void Validate(Process process, string dllPath)
        {
            // Determine if the process is running under WOW64
            
            Native.IsWow64Process(process.SafeHandle, out var isWow64);
            
            // Determine the architecture of the dll
            
            var peHeaders = new PeFile(dllPath);

            var is32Bit = peHeaders.Is32Bit;

            // Check if the process architecture matches the dll architecture

            if (isWow64 != is32Bit)
            {
                throw new ApplicationException("The architecture of the process did not match the architecture of the dll");
            }
        }
    }
}