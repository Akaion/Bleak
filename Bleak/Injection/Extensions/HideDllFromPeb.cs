using System;
using System.Text;
using System.Text.RegularExpressions;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native;

namespace Bleak.Injection.Extensions
{
    internal class HideDllFromPeb : IInjectionExtension
    {
        private readonly InjectionWrapper _injectionWrapper;

        public HideDllFromPeb(InjectionWrapper injectionWrapper)
        {
            _injectionWrapper = injectionWrapper;
        }

        public bool Call(InjectionContext injectionContext)
        {
            if (_injectionWrapper.RemoteProcess.IsWow64)
            {
                var filePathRegex = new Regex("System32", RegexOptions.IgnoreCase);

                foreach (var pebEntry in _injectionWrapper.RemoteProcess.GetWow64PebEntries())
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = _injectionWrapper.MemoryManager.ReadVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, pebEntry.FullDllName.Length);

                    var entryFilePath = filePathRegex.Replace(Encoding.Unicode.GetString(entryFilePathBytes), "SysWOW64");

                    if (entryFilePath != _injectionWrapper.DllPath)
                    {
                        continue;
                    }
                    
                    // Remove the entry from the doubly linked lists

                    RemoveDoublyLinkedListEntry(pebEntry.InLoadOrderLinks);

                    RemoveDoublyLinkedListEntry(pebEntry.InMemoryOrderLinks);

                    RemoveDoublyLinkedListEntry(pebEntry.InInitializationOrderLinks);

                    // Remove the entry from the LdrpHashTable

                    RemoveDoublyLinkedListEntry(pebEntry.HashLinks);

                    // Write over the DLL name and path

                    _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) pebEntry.BaseDllName.Buffer, new byte[pebEntry.BaseDllName.MaximumLength]);

                    _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, new byte[pebEntry.FullDllName.MaximumLength]);
                }
            }

            else
            {
                foreach (var pebEntry in _injectionWrapper.RemoteProcess.GetPebEntries())
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = _injectionWrapper.MemoryManager.ReadVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, pebEntry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    if (entryFilePath != _injectionWrapper.DllPath)
                    {
                        continue;
                    }
                    
                    // Remove the entry from the doubly linked lists

                    RemoveDoublyLinkedListEntry(pebEntry.InLoadOrderLinks);

                    RemoveDoublyLinkedListEntry(pebEntry.InMemoryOrderLinks);

                    RemoveDoublyLinkedListEntry(pebEntry.InInitializationOrderLinks);

                    // Remove the entry from the LdrpHashTable

                    RemoveDoublyLinkedListEntry(pebEntry.HashLinks);

                    // Write over the DLL name and path

                    _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) pebEntry.BaseDllName.Buffer, new byte[pebEntry.BaseDllName.MaximumLength]);

                    _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, new byte[pebEntry.FullDllName.MaximumLength]);
                }
            }

            return true;
        }

        private void RemoveDoublyLinkedListEntry(Structures.ListEntry32 entry)
        {
            // Read the previous entry from the list

            var previousEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<Structures.ListEntry32>((IntPtr) entry.Blink);

            // Change the front link of the previous entry to the front link of the entry

            previousEntry.Flink = entry.Flink;

            _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) entry.Blink, previousEntry);

            // Read the next entry from the list

            var nextEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<Structures.ListEntry32>((IntPtr) entry.Flink);

            // Change the back link of the next entry to the back link of the entry

            nextEntry.Blink = entry.Blink;

            _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) entry.Flink, nextEntry);
        }

        private void RemoveDoublyLinkedListEntry(Structures.ListEntry64 entry)
        {
            // Read the previous entry from the list

            var previousEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<Structures.ListEntry64>((IntPtr) entry.Blink);

            // Change the front link of the previous entry to the front link of the entry

            previousEntry.Flink = entry.Flink;

            _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) entry.Blink, previousEntry);

            // Read the next entry from the list

            var nextEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<Structures.ListEntry64>((IntPtr) entry.Flink);

            // Change the back link of the next entry to the back link of the entry

            nextEntry.Blink = entry.Blink;

            _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) entry.Flink, nextEntry);
        }
    }
}