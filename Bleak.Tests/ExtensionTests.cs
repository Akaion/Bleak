using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests
{
    public class ExtensionTests
    {
        private readonly Injector _injector;

        private readonly string _hostProcessName;

        private readonly string _dllPath;

        public ExtensionTests()
        {
            _injector = new Injector();

            // Get the name of the host process
            
            _hostProcessName = Process.GetCurrentProcess().ProcessName;
            
            // Get the root directory 
            
            var rootDirectory = Path.GetFullPath(@"..\..\..\Etc\");
            
            // Get the path to the test dll
            
            _dllPath = Path.Combine(rootDirectory, "TestDll.dll");
        }

        [Fact]
        public void TestEjectDll()
        {
            // Inject the test dll

            _injector.RtlCreateUserThread(_hostProcessName, _dllPath);
            
            // Eject the test dll
            
            Assert.True(_injector.EjectDll(_hostProcessName, _dllPath));
        }

        [Fact]
        public void TestEraseHeaders()
        {
            // Inject the test dll

            _injector.RtlCreateUserThread(_hostProcessName, _dllPath);
            
            // Erase the test dll headers
            
            Assert.True(_injector.EraseHeaders(_hostProcessName, _dllPath));
        }

        [Fact]
        public void TestRandomiseHeaders()
        {
            // Inject the test dll

            _injector.RtlCreateUserThread(_hostProcessName, _dllPath);
            
            // Erase the test dll headers
            
            Assert.True(_injector.RandomiseHeaders(_hostProcessName, _dllPath));
        }   
    }
}