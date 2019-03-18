using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests
{
    public class ExtensionTests : IDisposable
    {
        private readonly string DllPath;

        private readonly Injector Injector;

        private readonly Process Process;

        public ExtensionTests()
        {
            var etcDirectory = Path.GetFullPath(@"..\..\..\Etc\");

            DllPath = Path.Combine(etcDirectory, "TestDll.dll");

            Injector = new Injector();

            Process = new Process { StartInfo = { CreateNoWindow = true, FileName = "notepad.exe", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden } };

            Process.Start();

            Process.WaitForInputIdle();
        }

        public void Dispose()
        {
            Process.Kill();

            Process.Dispose();
        }
        
        [Fact]
        public void TestEjectDll()
        {
            Injector.CreateRemoteThread(Process.Id, DllPath);

            Assert.True(Injector.EjectDll(Process.Id, DllPath));
        }

        [Fact]
        public void EraseHeaders()
        {
            Injector.CreateRemoteThread(Process.Id, DllPath);

            Assert.True(Injector.EraseHeaders(Process.Id, DllPath));
        }

        [Fact]
        public void RandomiseHeaders()
        {
            Injector.CreateRemoteThread(Process.Id, DllPath);

            Assert.True(Injector.RandomiseHeaders(Process.Id, DllPath));
        }

        [Fact]
        public void UnlinkFromPeb()
        {
            Injector.CreateRemoteThread(Process.Id, DllPath);

            Assert.True(Injector.UnlinkFromPeb(Process.Id, DllPath));
        }
    }
}
