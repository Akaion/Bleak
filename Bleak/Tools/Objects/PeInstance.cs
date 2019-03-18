using Bleak.PortableExecutable;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Bleak.Tools.Objects
{
    internal class PeInstance : IDisposable
    {
        internal readonly PortableExecutableParser PeParser;

        internal readonly List<PortableExecutable.Objects.ExportedFunction> ExportedFunctions;

        internal PeInstance(string modulePath)
        {
            PeParser = new PortableExecutableParser(modulePath);

            ExportedFunctions = PeParser.GetExportedFunctions().ToList();
        }

        public void Dispose()
        {
            PeParser.Dispose();
        }
    }
}
