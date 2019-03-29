using Bleak.Native;
using Bleak.Wrappers;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Bleak.Extensions
{
    internal class UnlinkDllFromPeb
    {
        private readonly PropertyWrapper _propertyWrapper;

        internal UnlinkDllFromPeb(PropertyWrapper propertyWrapper)
        {
            _propertyWrapper = propertyWrapper;
        }

        internal bool Call()
        {
            var dllUnlinked = false;

            if (_propertyWrapper.TargetProcess.IsWow64)
            {
                var moduleFilePathRegex = new Regex("System32", RegexOptions.IgnoreCase);

                var pebEntries = _propertyWrapper.TargetProcess.GetWow64PebEntries();

                foreach (var pebEntry in pebEntries)
                {
                    // Read the file path of the module

                    var moduleFilePathBytes = _propertyWrapper.MemoryManager.ReadVirtualMemory((IntPtr)pebEntry.FullDllName.Buffer, pebEntry.FullDllName.Length);

                    var moduleFilePath = moduleFilePathRegex.Replace(Encoding.Default.GetString(moduleFilePathBytes).Replace("\0", ""), "SysWOW64");

                    if (moduleFilePath.Equals(_propertyWrapper.DllPath, StringComparison.OrdinalIgnoreCase))
                    {
                        // Unlink the module entry from the InLoadOrder doubly linked list

                        UnlinkEntryFromDoublyLinkedList(pebEntry.InLoadOrderLinks);

                        // Unlink the module entry from the InMemoryOrder doubly linked list

                        UnlinkEntryFromDoublyLinkedList(pebEntry.InMemoryOrderLinks);

                        // Unlink the module entry from the InInitOrder doubly linked list

                        UnlinkEntryFromDoublyLinkedList(pebEntry.InInitOrderLinks);

                        // Unlink the module entry from the LdrpHashTable

                        UnlinkEntryFromDoublyLinkedList(pebEntry.HashTableEntry);

                        // Write over the module entry with zeroes

                        _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) pebEntry.BaseDllName.Buffer, new byte[pebEntry.BaseDllName.MaximumLength]);

                        _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, new byte[pebEntry.FullDllName.MaximumLength]);

                        _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) pebEntries[pebEntries.IndexOf(pebEntry) - 1].InLoadOrderLinks.Flink, new byte[Marshal.SizeOf<Structures.LdrDataTableEntry32>()]);

                        dllUnlinked = true;

                        break;
                    }
                }
            }

            else
            {
                var pebEntries = _propertyWrapper.TargetProcess.GetPebEntries();

                foreach (var pebEntry in pebEntries)
                {
                    // Read the file path of the module

                    var moduleFilePathBytes = _propertyWrapper.MemoryManager.ReadVirtualMemory((IntPtr)pebEntry.FullDllName.Buffer, pebEntry.FullDllName.Length);

                    var moduleFilePath = Encoding.Default.GetString(moduleFilePathBytes).Replace("\0", "");

                    if (moduleFilePath.Equals(_propertyWrapper.DllPath, StringComparison.OrdinalIgnoreCase))
                    {
                        // Unlink the module entry from the InLoadOrder doubly linked list

                        UnlinkEntryFromDoublyLinkedList(pebEntry.InLoadOrderLinks);

                        // Unlink the module entry from the InMemoryOrder doubly linked list

                        UnlinkEntryFromDoublyLinkedList(pebEntry.InMemoryOrderLinks);

                        // Unlink the module entry from the InInitOrder doubly linked list

                        UnlinkEntryFromDoublyLinkedList(pebEntry.InInitOrderLinks);

                        // Unlink the module entry from the LdrpHashTable

                        UnlinkEntryFromDoublyLinkedList(pebEntry.HashTableEntry);

                        // Write over the module entry with zeroes

                        _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) pebEntry.BaseDllName.Buffer, new byte[pebEntry.BaseDllName.MaximumLength]);

                        _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, new byte[pebEntry.FullDllName.MaximumLength]);

                        _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) pebEntries[pebEntries.IndexOf(pebEntry) - 1].InLoadOrderLinks.Flink, new byte[Marshal.SizeOf<Structures.LdrDataTableEntry64>()]);

                        dllUnlinked = true;

                        break;
                    }
                }
            }

            if (!dllUnlinked)
            {
                var dllName = Path.GetFileName(_propertyWrapper.DllPath);

                throw new ArgumentException($"No DLL with the name {dllName} was found in the target processes module list");
            }

            return true;
        }

        private void UnlinkEntryFromDoublyLinkedList(Structures.ListEntry32 listEntry)
        {
            // Read the previous list entry from the doubly linked list

            var previousListEntry = _propertyWrapper.MemoryManager.ReadVirtualMemory<Structures.ListEntry32>((IntPtr) listEntry.Blink);

            // Change the front link of the previous list entry to the front link of the list entry

            previousListEntry.Flink = listEntry.Flink;

            _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) listEntry.Blink, previousListEntry);

            // Read the next list entry from the doubly linked list

            var nextListEntry = _propertyWrapper.MemoryManager.ReadVirtualMemory<Structures.ListEntry32>((IntPtr) listEntry.Flink);

            // Change the back link of the next list entry to the back link of the list entry

            nextListEntry.Blink = listEntry.Blink;

            _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) listEntry.Flink, nextListEntry);
        }

        private void UnlinkEntryFromDoublyLinkedList(Structures.ListEntry64 listEntry)
        {
            // Read the previous list entry from the doubly linked list

            var previousListEntry = _propertyWrapper.MemoryManager.ReadVirtualMemory<Structures.ListEntry64>((IntPtr) listEntry.Blink);

            // Change the front link of the previous list entry to the front link of the list entry

            previousListEntry.Flink = listEntry.Flink;

            _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) listEntry.Blink, previousListEntry);

            // Read the next list entry from the doubly linked list

            var nextListEntry = _propertyWrapper.MemoryManager.ReadVirtualMemory<Structures.ListEntry64>((IntPtr) listEntry.Flink);

            // Change the back link of the next list entry to the back link of the list entry

            nextListEntry.Blink = listEntry.Blink;

            _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) listEntry.Flink, nextListEntry);
        }
    }
}
