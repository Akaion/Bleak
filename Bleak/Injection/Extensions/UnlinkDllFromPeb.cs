using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native;
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Bleak.Injection.Extensions
{
    internal class UnlinkDllFromPeb : IInjectionExtension
    {
        public bool Call(InjectionProperties injectionProperties)
        {
            var dllUnlinked = false;

            if (injectionProperties.RemoteProcess.IsWow64)
            {
                var entryFilePathRegex = new Regex("System32", RegexOptions.IgnoreCase);

                foreach (var entry in injectionProperties.RemoteProcess.GetWow64PebEntries())
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = injectionProperties.MemoryManager.ReadVirtualMemory((IntPtr) entry.FullDllName.Buffer, entry.FullDllName.Length);

                    var entryFilePath = entryFilePathRegex.Replace(Encoding.Unicode.GetString(entryFilePathBytes), "SysWOW64");

                    if (entryFilePath.Equals(injectionProperties.DllPath, StringComparison.OrdinalIgnoreCase))
                    {
                        // Remove the entry from the doubly linked lists

                        RemoveDoublyLinkedListEntry(injectionProperties, entry.InLoadOrderLinks);

                        RemoveDoublyLinkedListEntry(injectionProperties, entry.InMemoryOrderLinks);

                        RemoveDoublyLinkedListEntry(injectionProperties, entry.InInitializationOrderLinks);

                        // Remove the entry from the LdrpHashTable

                        RemoveDoublyLinkedListEntry(injectionProperties, entry.HashLinks);

                        // Write over the entry strings with zeroes

                        injectionProperties.MemoryManager.WriteVirtualMemory((IntPtr) entry.BaseDllName.Buffer, new byte[entry.BaseDllName.MaximumLength]);

                        injectionProperties.MemoryManager.WriteVirtualMemory((IntPtr) entry.FullDllName.Buffer, new byte[entry.FullDllName.MaximumLength]);

                        dllUnlinked = true;

                        break;
                    }
                }
            }

            else
            {
                foreach (var entry in injectionProperties.RemoteProcess.GetPebEntries())
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = injectionProperties.MemoryManager.ReadVirtualMemory((IntPtr) entry.FullDllName.Buffer, entry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    if (entryFilePath.Equals(injectionProperties.DllPath, StringComparison.OrdinalIgnoreCase))
                    {
                        // Remove the entry from the doubly linked lists

                        RemoveDoublyLinkedListEntry(injectionProperties, entry.InLoadOrderLinks);

                        RemoveDoublyLinkedListEntry(injectionProperties, entry.InMemoryOrderLinks);

                        RemoveDoublyLinkedListEntry(injectionProperties, entry.InInitializationOrderLinks);

                        // Remove the entry from the LdrpHashTable

                        RemoveDoublyLinkedListEntry(injectionProperties, entry.HashLinks);

                        // Write over the entry strings with zeroes

                        injectionProperties.MemoryManager.WriteVirtualMemory((IntPtr)entry.BaseDllName.Buffer, new byte[entry.BaseDllName.MaximumLength]);

                        injectionProperties.MemoryManager.WriteVirtualMemory((IntPtr)entry.FullDllName.Buffer, new byte[entry.FullDllName.MaximumLength]);

                        dllUnlinked = true;

                        break;
                    }
                }
            }

            if (!dllUnlinked)
            {
                throw new ArgumentException($"No DLL with the name {Path.GetFileName(injectionProperties.DllPath)} was found in the target processes module list");
            }

            return true;
        }

        private void RemoveDoublyLinkedListEntry(InjectionProperties injectionProperties, Structures.ListEntry32 entry)
        {
            // Read the previous entry from the doubly linked list

            var previousEntry = injectionProperties.MemoryManager.ReadVirtualMemory<Structures.ListEntry32>((IntPtr)entry.Blink);

            // Change the front link of the previous entry to the front link of the entry

            previousEntry.Flink = entry.Flink;

            injectionProperties.MemoryManager.WriteVirtualMemory((IntPtr) entry.Blink, previousEntry);

            // Read the next entry from the doubly linked list

            var nextEntry = injectionProperties.MemoryManager.ReadVirtualMemory<Structures.ListEntry32>((IntPtr) entry.Flink);

            // Change the back link of the next entry to the back link of the entry

            nextEntry.Blink = entry.Blink;

            injectionProperties.MemoryManager.WriteVirtualMemory((IntPtr) entry.Flink, nextEntry);
        }

        private void RemoveDoublyLinkedListEntry(InjectionProperties injectionProperties, Structures.ListEntry64 entry)
        {
            // Read the previous entry from the doubly linked list

            var previousEntry = injectionProperties.MemoryManager.ReadVirtualMemory<Structures.ListEntry64>((IntPtr) entry.Blink);

            // Change the front link of the previous entry to the front link of the entry

            previousEntry.Flink = entry.Flink;

            injectionProperties.MemoryManager.WriteVirtualMemory((IntPtr) entry.Blink, previousEntry);

            // Read the next entry from the doubly linked list

            var nextEntry = injectionProperties.MemoryManager.ReadVirtualMemory<Structures.ListEntry64>((IntPtr) entry.Flink);

            // Change the back link of the next entry to the back link of the entry

            nextEntry.Blink = entry.Blink;

            injectionProperties.MemoryManager.WriteVirtualMemory((IntPtr) entry.Flink, nextEntry);
        }
    }
}
