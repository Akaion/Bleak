using Bleak.Native;
using Bleak.Syscall.Shellcode;
using Bleak.Tools;
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace Bleak.Syscall
{
    internal class Tools
    {
        private readonly Lazy<IntPtr> NtDllAddress;

        private int ShellcodeSize;

        internal Tools()
        {
            NtDllAddress = new Lazy<IntPtr>(GetNtDllAddress);
        }

        internal void FreeMemoryForSyscall<TDelegate>(TDelegate syscallDelegate) where TDelegate : class
        {
            // Get the address of the buffer allocated for the shellcode used to perform the syscall

            var shellcodeBuffer = Marshal.GetFunctionPointerForDelegate(syscallDelegate);

            // Free the memory allocated for the buffer

            MemoryTools.FreeMemoryForBuffer(shellcodeBuffer, ShellcodeSize);
        }

        internal TDelegate CreateDelegateForSyscall<TDelegate>() where TDelegate : class
        {
            var syscallIndex = GetSyscallIndex(typeof(TDelegate).Name.Replace("Definition", ""));

            // Create the shellcode used to perform the syscall

            var syscallShellcode = Environment.Is64BitProcess ? SyscallX64.GetShellcode(syscallIndex) : SyscallX86.GetShellcode(syscallIndex);

            ShellcodeSize = syscallShellcode.Length;

            // Store the shellcode in a buffer

            var shellcodeBuffer = MemoryTools.AllocateMemoryForBuffer(ShellcodeSize);

            Marshal.Copy(syscallShellcode, 0, shellcodeBuffer, ShellcodeSize);

            // Create a delegate to perform the syscall

            return Marshal.GetDelegateForFunctionPointer<TDelegate>(shellcodeBuffer);
        }

        private static IntPtr GetNtDllAddress()
        {
            return Process.GetCurrentProcess().Modules.Cast<ProcessModule>().First(module => module.ModuleName == "ntdll.dll").BaseAddress;
        }

        private uint GetSyscallIndex(string functionName)
        {
            // Get the address of the function

            var functionAddress = PInvoke.GetProcAddress(NtDllAddress.Value, functionName);

            // Copy the first 8 bytes of the function

            var functionBytes = new byte[8];

            Marshal.Copy(functionAddress, functionBytes, 0, 8);

            // Retrieve the syscall index from the first 8 bytes of the function

            var syscallIndexBytes = Environment.Is64BitProcess ? functionBytes.Skip(4).Take(4) : functionBytes.Skip(1).Take(4);

            return BitConverter.ToUInt32(syscallIndexBytes.ToArray(), 0);
        } 
    }
}
