using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests
{
    public class MethodTests : IDisposable
    {
        private readonly string _dllPath;

        private readonly Injector _injector;

        private readonly Process _process;

        public MethodTests()
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
        public void TestCreateRemoteThread()
        {
            Assert.True(_injector.CreateRemoteThread(_process.Id, _dllPath));
        }

        [Fact]
        public void TestManualMap()
        {
            Assert.True(_injector.ManualMap(_process.Id, _dllPath));
        }

        [Fact]
        public void TestQueueUserApc()
        {
            Assert.True(_injector.QueueUserApc(_process.Id, _dllPath));
        }

        [Fact]
        public void TestRtlCreateUserThread()
        {
            Assert.True(_injector.RtlCreateUserThread(_process.Id, _dllPath));
        }

        [Fact]
        public void TestSetThreadContext()
        {
            Assert.True(_injector.SetThreadContext(_process.Id, _dllPath));
        }
    }
}
