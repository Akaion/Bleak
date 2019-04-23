using Bleak.PortableExecutable;
using Bleak.PortableExecutable.Objects;
using System;
using System.Collections.Generic;

namespace Bleak.RemoteProcess.Objects
{
    internal class PeInstance : IDisposable
    {
        internal readonly PeParser PeParser;

        internal readonly List<ExportedFunction> ExportedFunctions;

        internal PeInstance(string modulePath)
        {
            PeParser = new PeParser(modulePath);

            ExportedFunctions = PeParser.GetExportedFunctions();
        }

        public void Dispose()
        {
            PeParser.Dispose();
        }
    }
}
