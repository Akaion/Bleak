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
            // Determine if the remote process is running under WOW64
            
            Native.IsWow64Process(process.SafeHandle, out var isWow64);
            
            // Determine the architecture of the dll
            
            var peHeaders = new PeFile(dllPath);
            
            var is32Bit = peHeaders.Is32Bit;
            
            // Check if the remote process architecture matches the dll architecture
            
            if (isWow64 != is32Bit)
            {
                throw new ApplicationException("The architecture of the process did not match the architecture of the dll");
            }
            
            // Ensure that x64 injection is not being attempted from an x86 process

            if (!Environment.Is64BitProcess && isWow64)
            {
                throw new ApplicationException("x64 injection is not supported when compiled as x86");
            }
        }
    }
}