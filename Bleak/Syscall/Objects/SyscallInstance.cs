using Bleak.Memory;
using System;

namespace Bleak.Syscall.Objects
{
    internal class SyscallInstance : IDisposable
    {
        internal readonly Delegate SyscallDelegate;

        internal readonly IntPtr ShellcodeAddress;

        internal SyscallInstance(Delegate syscallDelegate, IntPtr shellcodeAddress)
        {
            SyscallDelegate = syscallDelegate;

            ShellcodeAddress = shellcodeAddress;
        }

        public void Dispose()
        {
            LocalMemoryTools.FreeMemoryForBuffer(ShellcodeAddress);
        }
    }
}
