using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests.x86
{
    public class Tests : IDisposable
    {
        // Create an instance of an Injector
        
        private readonly Injector _injector = new Injector();

        // Path to test dll

        private readonly string _dllPath = Path.GetFullPath(@"..\..\") + "Test-Dll-x86.dll";
        
        // Path to test process

        private readonly string _processPath = Path.GetFullPath(@"..\..\");
        
        // Test process

        private readonly Process _process;
        
        public Tests()
        {
            // Create a new test process

            _process = new Process { StartInfo = { CreateNoWindow = true, WorkingDirectory = _processPath, FileName = "TestProcess.exe" } };

            _process.Start();
        }

        public void Dispose()
        {
            // Terminate the test process
            
            _process.Kill();       
        }
        
        [Fact]
        public void TestCreateRemoteThread()
        {
            Assert.True(_injector.CreateRemoteThread(_dllPath, _process.Id));
        }

        [Fact]
        public void TestNtCreateThreadEx()
        {
            Assert.True(_injector.NtCreateThreadEx(_dllPath, _process.Id));
        }
        
        [Fact]
        public void TestManualMap()
        {
            Assert.True(_injector.ManualMap(_dllPath, _process.Id));
        }
        
        [Fact]
        public void TestQueueUserAPC()
        {
            Assert.True(_injector.QueueUserAPC(_dllPath, _process.Id));
        }
        
        [Fact]
        public void TestRtlCreateUserThread()
        {
            Assert.True(_injector.RtlCreateUserThread(_dllPath, _process.Id));
        }
        
        [Fact]
        public void TestSetThreadContext()
        {
            Assert.True(_injector.SetThreadContext(_dllPath, _process.Id));
        }

        [Fact]
        public void TestZwCreateThreadEx()
        {
            Assert.True(_injector.ZwCreateThreadEx(_dllPath, _process.Id));
        }

        [Fact]
        public void TestEraseHeaders()
        {
            _injector.RtlCreateUserThread(_dllPath, _process.Id);
            
            Assert.True(_injector.EraseHeaders(_dllPath, _process.Id));
        }
        
        [Fact]
        public void TestRandomiseHeaders()
        {
           _injector.RtlCreateUserThread(_dllPath, _process.Id);
           
           Assert.True(_injector.RandomiseHeaders(_dllPath, _process.Id));
        }
    }
}