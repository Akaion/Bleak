using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests
{
    public class MethodTests : IDisposable
    {
        private readonly string DllPath;

        private readonly Injector Injector;

        private readonly Process Process;

        public MethodTests()
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
        public void TestCreateRemoteThread()
        {
            Assert.True(Injector.CreateRemoteThread(Process.Id, DllPath));
        }

        [Fact]
        public void TestManualMap()
        {
            Assert.True(Injector.ManualMap(Process.Id, DllPath));
        }

        [Fact]
        public void TestNtCreateThreadEx()
        {
            Assert.True(Injector.NtCreateThreadEx(Process.Id, DllPath));
        }

        [Fact]
        public void TestQueueUserApc()
        {
            Assert.True(Injector.QueueUserApc(Process.Id, DllPath));
        }

        [Fact]
        public void TestRtlCreateUserThread()
        {
            Assert.True(Injector.RtlCreateUserThread(Process.Id, DllPath));
        }

        [Fact]
        public void TestSetThreadContext()
        {
            Assert.True(Injector.SetThreadContext(Process.Id, DllPath));
        }
    }
}
