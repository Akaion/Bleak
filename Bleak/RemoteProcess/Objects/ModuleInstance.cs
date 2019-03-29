using System;

namespace Bleak.RemoteProcess.Objects
{
    internal class ModuleInstance
    {
        internal readonly IntPtr BaseAddress;

        internal readonly string FilePath;

        internal readonly string Name;

        internal ModuleInstance(IntPtr baseAddress, string filePath, string name)
        {
            BaseAddress = baseAddress;

            FilePath = filePath;

            Name = name;
        }
    }
}
