using System.ComponentModel;
using System.Runtime.InteropServices;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native;
using Bleak.Shared;

namespace Bleak.Injection.Extensions
{
    internal class EjectDll : IInjectionExtension
    {
        private readonly InjectionWrapper _injectionWrapper;

        public EjectDll(InjectionWrapper injectionWrapper)
        {
            _injectionWrapper = injectionWrapper;
        }

        public bool Call(InjectionContext injectionContext)
        {
            var dllBaseAddress = injectionContext.DllBaseAddress;

            if (_injectionWrapper.InjectionMethod == InjectionMethod.ManualMap)
            {
                // Get the address of the entry point of the DLL in the remote process

                var dllEntryPointAddress = _injectionWrapper.RemoteProcess.IsWow64
                                         ? dllBaseAddress.AddOffset(_injectionWrapper.PeParser.GetPeHeaders().NtHeaders32.OptionalHeader.AddressOfEntryPoint)
                                         : dllBaseAddress.AddOffset(_injectionWrapper.PeParser.GetPeHeaders().NtHeaders64.OptionalHeader.AddressOfEntryPoint);

                // Calculate the address of the exception table

                var exceptionTable = _injectionWrapper.RemoteProcess.IsWow64
                                   ? _injectionWrapper.PeParser.GetPeHeaders().NtHeaders32.OptionalHeader.DataDirectory[3]
                                   : _injectionWrapper.PeParser.GetPeHeaders().NtHeaders64.OptionalHeader.DataDirectory[3];

                var exceptionTableAddress = dllBaseAddress.AddOffset(exceptionTable.VirtualAddress);

                // Call the DllMain function of the DLL with DllProcessDetach in the remote process

                if (!_injectionWrapper.RemoteProcess.CallFunction<bool>(CallingConvention.StdCall, dllEntryPointAddress, (ulong) dllBaseAddress, Constants.DllProcessDetach, 0))
                {
                    throw new Win32Exception("Failed to call DllMain in the remote process");
                }

                if (_injectionWrapper.RemoteProcess.IsWow64)
                {
                    var ntdll = _injectionWrapper.RemoteProcess.Modules.Find(module => module.Name == "ntdll.dll");

                    // Ensure the PDB has been downloaded
                
                    while (!_injectionWrapper.PdbParser.Value.PdbDownloaded) { }
                
                    // Get the address of the RtlRemoveInvertedFunctionTable function

                    var rtlRemoveInvertedFunctionTableSymbol = _injectionWrapper.PdbParser.Value.PdbSymbols.Find(symbol => symbol.Name == "_RtlRemoveInvertedFunctionTable@4");

                    var rtlRemoveInvertedFunctionTableSection = ntdll.PeParser.Value.GetPeHeaders().SectionHeaders[(int) rtlRemoveInvertedFunctionTableSymbol.Section - 1];
                
                    var rtlRemoveInvertedFunctionTableAddress = ntdll.BaseAddress.AddOffset(rtlRemoveInvertedFunctionTableSection.VirtualAddress + rtlRemoveInvertedFunctionTableSymbol.Offset);

                    // Remove the DLL from the LdrpInvertedFunctionTable
                
                    _injectionWrapper.RemoteProcess.CallFunction(CallingConvention.FastCall, rtlRemoveInvertedFunctionTableAddress, (ulong) injectionContext.DllBaseAddress);
                }

                else
                {
                    // Remove the exception table from the dynamic function table of the remote process

                    if (!_injectionWrapper.RemoteProcess.CallFunction<bool>(CallingConvention.StdCall, "kernel32.dll", "RtlDeleteFunctionTable", (ulong) exceptionTableAddress))
                    {
                        throw new Win32Exception("Failed to remove an exception table from the dynamic function table of the remote process");
                    }
                }
                
                

                // Free the memory previously allocated for the DLL in the remote process

                _injectionWrapper.MemoryManager.FreeVirtualMemory(dllBaseAddress);
            }

            else
            {
                if (!_injectionWrapper.RemoteProcess.CallFunction<bool>(CallingConvention.StdCall, "kernel32.dll", "FreeLibrary", (ulong) dllBaseAddress))
                {
                    throw new Win32Exception("Failed to call FreeLibrary in the remote process");
                }
            }

            return true;
        }
    }
}