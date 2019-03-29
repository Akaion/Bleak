using Bleak.PortableExecutable;
using Bleak.PortableExecutable.Objects;
using Bleak.Syscall.Shellcode;
using Bleak.Tools;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace Bleak.Syscall
{
    internal class Tools : IDisposable
    {
        private readonly IntPtr _ntDllAddress;

        private readonly List<ExportedFunction> _ntDllFunctions;

        private readonly List<IntPtr> _shellcodeAddresses;

        internal Tools()
        {
            _ntDllAddress = GetNtDllAddress();

            _ntDllFunctions = GetNtDllFunctions();

            _shellcodeAddresses = new List<IntPtr>();
        }

        public void Dispose()
        {
            foreach (var shellcodeAddress in _shellcodeAddresses)
            {
                // Free the memory allocated for the shellcode

                MemoryTools.FreeMemoryForBuffer(shellcodeAddress);
            }
        }

        internal TDelegate CreateDelegateForSyscall<TDelegate>() where TDelegate : class
        {
            // Get the address of the function

            var functionAddress = _ntDllAddress + (int) _ntDllFunctions.Find(function => function.Name == typeof(TDelegate).Name.Replace("Definition", "")).Offset;

            // Copy the first 8 bytes of the function

            var functionBytes = new byte[8];

            Marshal.Copy(functionAddress, functionBytes, 0, 8);

            // Retrieve the syscall index from the bytes

            var syscallIndexBytes = Environment.Is64BitProcess ? functionBytes.Skip(4).Take(4) : functionBytes.Skip(1).Take(4);

            var syscallIndex = BitConverter.ToUInt32(syscallIndexBytes.ToArray(), 0);

            // Create the shellcode used to perform the syscall

            var shellcode = Environment.Is64BitProcess ? SyscallX64.GetShellcode(syscallIndex) : SyscallX86.GetShellcode(syscallIndex);

            // Store the shellcode in a buffer

            var shellcodeBuffer = MemoryTools.AllocateMemoryForBuffer(shellcode.Length);

            _shellcodeAddresses.Add(shellcodeBuffer);
            
            Marshal.Copy(shellcode, 0, shellcodeBuffer, shellcode.Length);

            // Create a delegate to perform the syscall

            return Marshal.GetDelegateForFunctionPointer<TDelegate>(shellcodeBuffer);
        }

        private IntPtr GetNtDllAddress()
        {
            return Process.GetCurrentProcess().Modules.Cast<ProcessModule>().First(module => module.ModuleName == "ntdll.dll").BaseAddress;
        }

        private List<ExportedFunction> GetNtDllFunctions()
        {
            var ntDllPath = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().First(module => module.ModuleName == "ntdll.dll").FileName;

            using (var peParser = new PortableExecutableParser(ntDllPath))
            {
                return peParser.GetExportedFunctions();
            }
        }
    }
}
