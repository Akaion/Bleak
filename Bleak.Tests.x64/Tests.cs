using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests.x64
{
    public class Tests : IDisposable
    {
        // Create an instance of an Injector

        private readonly Injector _injector = new Injector();

        private readonly string _dllPath;

        private readonly Process _process;

        public Tests()
        {
            // Get the root directory

            var rootDirectory = Path.GetFullPath(@"..\..\");
            
            // Get the path to the test dll

            _dllPath = rootDirectory + "Test-Dll-x64.dll";
            
            // Initialise a test process

            _process = new Process { StartInfo = { CreateNoWindow = true, WorkingDirectory = rootDirectory, FileName = "TestProcess.exe" } };

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
        public void TestManualMap()
        {
            Assert.True(_injector.ManualMap(_dllPath, _process.Id));
        }
        
        [Fact]
        public void TestNtCreateTheadEx()
        {
            Assert.True(_injector.NtCreateThreadEx(_dllPath, _process.Id));
        }

        [Fact]
        public void TestQueueUserApc()
        {
            Assert.True(_injector.QueueUserApc(_dllPath, _process.Id));
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
        public void TestEjectDll()
        {   
            _injector.RtlCreateUserThread(_dllPath, _process.Id);
            
            Assert.True(_injector.EjectDll(_dllPath, _process.Id));
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