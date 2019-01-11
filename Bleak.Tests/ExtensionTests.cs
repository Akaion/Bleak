using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests
{
    public class ExtensionTests : IDisposable
    {
        private readonly Injector _injector;

        private readonly Process _process;

        private readonly string _dllPath;

        public ExtensionTests()
        {
            _injector = new Injector();
            
            // Get the root directory 
            
            var rootDirectory = Path.GetFullPath(@"..\..\..\Etc\");
            
            // Initialize a test process
            
            _process = new Process { StartInfo = {CreateNoWindow = true, FileName = "notepad.exe" } };

            _process.Start();
            
            // Get the path to the test dll
            
            _dllPath = Path.Combine(rootDirectory, "TestDll.dll");
        }
        
        public void Dispose()
        {
            // Terminate the test process

            _process.Kill();
        }

        [Fact]
        public void TestEjectDll()
        {
            // Inject the test dll

            _injector.RtlCreateUserThread(_process.Id, _dllPath);
            
            // Eject the test dll
            
            Assert.True(_injector.EjectDll(_process.Id, _dllPath));
        }

        [Fact]
        public void TestEraseHeaders()
        {
            // Inject the test dll

            _injector.RtlCreateUserThread(_process.Id, _dllPath);
            
            // Erase the test dll headers
            
            Assert.True(_injector.EraseHeaders(_process.Id, _dllPath));
        }

        [Fact]
        public void TestRandomiseHeaders()
        {
            // Inject the test dll

            _injector.RtlCreateUserThread(_process.Id, _dllPath);
            
            // Erase the test dll headers
            
            Assert.True(_injector.RandomiseHeaders(_process.Id, _dllPath));
        }

        [Fact]
        public void TestUnlinkFromPeb()
        {
            // Inject the test dll

            _injector.RtlCreateUserThread(_process.Id, _dllPath);
            
            // Unlink the dll from the peb
            
            Assert.True(_injector.UnlinkFromPeb(_process.Id, _dllPath));
        }
    }
}