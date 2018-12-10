using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests.x86
{
    public class ExtensionTests : IDisposable
    {
        // Create an instance of an Injector

        private readonly Injector _injector = new Injector();

        private readonly string _dllPath;

        private readonly Process _process;

        public ExtensionTests()
        {
            // Get the root directory
            
            var rootDirectory = Path.GetFullPath(@"..\..\Etc\");
            
            // Get the path to the test dll

            _dllPath = Path.Combine(rootDirectory, "Test-Dll-x86.dll");
            
            // Get the path to the test process

            var processPath = Path.Combine(rootDirectory, "TestProcess.exe");
            
            // Initialise a test process

            _process = new Process { StartInfo = { CreateNoWindow = true, FileName = processPath } };

            _process.Start();
        }
        
        public void Dispose()
        {
            // Terminate the test process

            _process.Kill();
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