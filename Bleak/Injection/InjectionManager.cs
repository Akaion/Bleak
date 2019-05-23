using System;
using System.Collections.Generic;
using Bleak.Handlers;
using Bleak.Injection.Extensions;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;

namespace Bleak.Injection
{
    internal class InjectionManager : IDisposable
    {
        private readonly InjectionContext _injectionContext;

        private readonly Dictionary<string, IInjectionExtension> _injectionExtensionCache;

        private readonly IInjectionMethod _injectionMethod;

        private readonly InjectionWrapper _injectionWrapper;

        internal InjectionManager(InjectionMethod injectionMethod, int processId, byte[] dllBytes)
        {
            _injectionContext = new InjectionContext();

            _injectionWrapper = new InjectionWrapper(injectionMethod, processId, dllBytes);

            _injectionExtensionCache = new Dictionary<string, IInjectionExtension>
            {
                { "EjectDll", new EjectDll(_injectionWrapper) },
                { "HideDllFromPeb", new HideDllFromPeb(_injectionWrapper) },
                { "RandomiseDllHeaders", new RandomiseDllHeaders(_injectionWrapper) }
            };

            var injectionMethodType = Type.GetType("Bleak.Injection.Methods." + injectionMethod);

            _injectionMethod = (IInjectionMethod) Activator.CreateInstance(injectionMethodType, _injectionWrapper);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
        }

        internal InjectionManager(InjectionMethod injectionMethod, int processId, string dllPath)
        {
            _injectionContext = new InjectionContext();

            _injectionWrapper = new InjectionWrapper(injectionMethod, processId, dllPath);

            _injectionExtensionCache = new Dictionary<string, IInjectionExtension>
            {
                { "EjectDll", new EjectDll(_injectionWrapper) },
                { "HideDllFromPeb", new HideDllFromPeb(_injectionWrapper) },
                { "RandomiseDllHeaders", new RandomiseDllHeaders(_injectionWrapper) }
            };

            var injectionMethodType = Type.GetType("Bleak.Injection.Methods." + injectionMethod);

            _injectionMethod = (IInjectionMethod) Activator.CreateInstance(injectionMethodType, _injectionWrapper);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
        }

        internal InjectionManager(InjectionMethod injectionMethod, string processName, byte[] dllBytes)
        {
            _injectionContext = new InjectionContext();

            _injectionWrapper = new InjectionWrapper(injectionMethod, processName, dllBytes);

            _injectionExtensionCache = new Dictionary<string, IInjectionExtension>
            {
                { "EjectDll", new EjectDll(_injectionWrapper) },
                { "HideDllFromPeb", new HideDllFromPeb(_injectionWrapper) },
                { "RandomiseDllHeaders", new RandomiseDllHeaders(_injectionWrapper) }
            };

            var injectionMethodType = Type.GetType("Bleak.Injection.Methods." + injectionMethod);

            _injectionMethod = (IInjectionMethod) Activator.CreateInstance(injectionMethodType, _injectionWrapper);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
        }

        internal InjectionManager(InjectionMethod injectionMethod, string processName, string dllPath)
        {
            _injectionContext = new InjectionContext();

            _injectionWrapper = new InjectionWrapper(injectionMethod, processName, dllPath);

            _injectionExtensionCache = new Dictionary<string, IInjectionExtension>
            {
                { "EjectDll", new EjectDll(_injectionWrapper) },
                { "HideDllFromPeb", new HideDllFromPeb(_injectionWrapper) },
                { "RandomiseDllHeaders", new RandomiseDllHeaders(_injectionWrapper) }
            };

            var injectionMethodType = Type.GetType("Bleak.Injection.Methods." + injectionMethod);

            _injectionMethod = (IInjectionMethod) Activator.CreateInstance(injectionMethodType, _injectionWrapper);

            // Ensure the architecture of the DLL is valid

            ValidationHandler.ValidateDllArchitecture(_injectionWrapper);
        }

        public void Dispose()
        {
            _injectionWrapper.Dispose();
        }

        internal bool EjectDll()
        {
            if (!_injectionContext.Injected)
            {
                return true;
            }

            if (_injectionExtensionCache["EjectDll"].Call(_injectionContext))
            {
                _injectionContext.DllBaseAddress = IntPtr.Zero;

                _injectionContext.Injected = false;
            }

            return !_injectionContext.Injected;
        }

        internal bool HideDllFromPeb()
        {
            if (_injectionContext.PebEntryHidden || !_injectionContext.Injected || _injectionWrapper.InjectionMethod == InjectionMethod.ManualMap)
            {
                return true;
            }

            if(_injectionExtensionCache["HideDllFromPeb"].Call(_injectionContext))
            {
                _injectionContext.PebEntryHidden = true;
            }

            return _injectionContext.PebEntryHidden;
        }

        internal IntPtr InjectDll()
        {
            if (_injectionContext.Injected)
            {
                return _injectionContext.DllBaseAddress;
            }

            _injectionContext.DllBaseAddress = _injectionMethod.Call();

            if (_injectionContext.DllBaseAddress != IntPtr.Zero)
            {
                _injectionWrapper.RemoteProcess.Refresh();
                
                _injectionContext.Injected = true;
            }

            return _injectionContext.DllBaseAddress;
        }

        internal bool RandomiseDllHeaders()
        {
            if (_injectionContext.HeadersRandomised || !_injectionContext.Injected)
            {
                return true;
            }

            if(_injectionExtensionCache["RandomiseDllHeaders"].Call(_injectionContext))
            {
                _injectionContext.HeadersRandomised = true;
            }

            return _injectionContext.HeadersRandomised;
        }
    }
}