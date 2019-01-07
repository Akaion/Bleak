using System.Diagnostics;
using System.IO;
using Xunit;

namespace Bleak.Tests
{
    public class MethodTests
    {
        private readonly Injector _injector;

        private readonly string _hostProcessName;

        private readonly string _dllPath;
        
        public MethodTests()
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
        public void TestCreateRemoteThread()
        {
            // Inject the test dll
            
            Assert.True(_injector.CreateRemoteThread(_hostProcessName, _dllPath));
        }

        [Fact]
        public void TestManualMap()
        {
            // Inject the test dll
            
            Assert.True(_injector.ManualMap(_hostProcessName, _dllPath));
        }

        [Fact]
        public void TestNtCreateThreadEx()
        {
            // Inject the test dll
            
            Assert.True(_injector.NtCreateThreadEx(_hostProcessName, _dllPath));
        }

        [Fact]
        public void TestQueueUserApc()
        {
            // Inject the test dll
            
            Assert.True(_injector.QueueUserApc(_hostProcessName, _dllPath));
        }

        [Fact]
        public void TestRtlCreateUserThread()
        {
            // Inject the test dll
            
            Assert.True(_injector.RtlCreateUserThread(_hostProcessName, _dllPath));
        }

        [Fact]
        public void TestSetThreadContext()
        {
            // Inject the test dll
            
            Assert.True(_injector.SetThreadContext(_hostProcessName, _dllPath));
        }

        [Fact]
        public void TestZwCreateThreadEx()
        {
            // Inject the test dll
            
            Assert.True(_injector.ZwCreateThreadEx(_hostProcessName, _dllPath));
        }
    }
}