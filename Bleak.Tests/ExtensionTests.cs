using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests
{
    public class ExtensionTests : IDisposable
    {
        private readonly string _dllPath;

        private readonly Injector _injector;

        private readonly Process _process;

        public ExtensionTests()
        {
            _dllPath = Path.Combine(Path.GetFullPath(@"..\..\..\Etc\"), "TestDll.dll");

            _injector = new Injector();

            _process = new Process { StartInfo = { CreateNoWindow = true, FileName = "notepad.exe", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden } };

            _process.Start();

            _process.WaitForInputIdle();
        }

        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }

        [Fact]
        public void TestEjectDll()
        {
            _injector.CreateRemoteThread(_process.Id, _dllPath);

            Assert.True(_injector.EjectDll(_process.Id, _dllPath));
        }

        [Fact]
        public void TestEraseDllHeaders()
        {
            _injector.CreateRemoteThread(_process.Id, _dllPath);

            Assert.True(_injector.EraseDllHeaders(_process.Id, _dllPath));
        }

        [Fact]
        public void TestRandomiseDllHeaders()
        {
            _injector.CreateRemoteThread(_process.Id, _dllPath);

            Assert.True(_injector.RandomiseDllHeaders(_process.Id, _dllPath));
        }

        [Fact]
        public void UnlinkDllFromPeb()
        {
            _injector.CreateRemoteThread(_process.Id, _dllPath);

            Assert.True(_injector.UnlinkDllFromPeb(_process.Id, _dllPath));
        }
    }
}
