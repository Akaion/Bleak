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
            // Get the root directory
            
            var rootDirectory = Path.GetFullPath(@"..\..\..\Etc\");
            
            // Get the path to the test dll
            
            _dllPath = Path.Combine(rootDirectory, "TestDll.dll");
            
            // Initialize an injector instance
            
            _injector = new Injector();
            
            // Initialize a test process
            
            _process = new Process { StartInfo = {CreateNoWindow = true, FileName = "notepad.exe", UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden} };

            _process.Start();

            _process.WaitForInputIdle();
        }

        public void Dispose()
        {
            // Terminate the test process

            _process?.Kill();
        }

        [Fact]
        public void TestCreateRemoteThread()
        {
            // Inject the test dll
            
            Assert.True(_injector.CreateRemoteThread(_process.Id, _dllPath));
        }

        [Fact]
        public void TestManualMap()
        {
            // Inject the test dll
            
            Assert.True(_injector.ManualMap(_process.Id, _dllPath));
        }

        [Fact]
        public void TestNtCreateThreadEx()
        {
            // Inject the test dll
            
            Assert.True(_injector.NtCreateThreadEx(_process.Id, _dllPath));
        }

        [Fact]
        public void TestQueueUserApc()
        {
            // Inject the test dll
            
            Assert.True(_injector.QueueUserApc(_process.Id, _dllPath));
        }

        [Fact]
        public void TestRtlCreateUserThread()
        {
            // Inject the test dll
            
            Assert.True(_injector.RtlCreateUserThread(_process.Id, _dllPath));
        }

        [Fact]
        public void TestSetThreadContext()
        {
            // Inject the test dll
            
            Assert.True(_injector.SetThreadContext(_process.Id, _dllPath));
        }

        [Fact]
        public void TestZwCreateThreadEx()
        {
            // Inject the test dll
            
            Assert.True(_injector.ZwCreateThreadEx(_process.Id, _dllPath));
        }
    }
}