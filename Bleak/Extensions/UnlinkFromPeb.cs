using Bleak.Extensions.Interfaces;
using Bleak.Native;
using Bleak.Tools;
using Bleak.Wrappers;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Bleak.Extensions
{
    internal class UnlinkFromPeb : IExtensionMethod
    {
        private readonly PropertyWrapper PropertyWrapper;

        internal UnlinkFromPeb(PropertyWrapper propertyWrapper)
        {
            PropertyWrapper = propertyWrapper;
        }

        public bool Call()
        {
            var memoryManager = PropertyWrapper.MemoryManager.Value;

            if (PropertyWrapper.IsWow64Process.Value)
            {
                // Query the target process for the base address of the peb

                var pebBaseAddressBuffer = (IntPtr) PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtQueryInformationProcess>(PropertyWrapper.ProcessHandle.Value, Enumerations.ProcessInformationClass.Wow64Information);

                // Marshal the base address of the peb from the buffer

                var pebBaseAddress = Marshal.PtrToStructure<ulong>(pebBaseAddressBuffer);

                // Read the peb from the target process

                var peb = memoryManager.ReadMemory<Structures.Peb32>((IntPtr) pebBaseAddress);

                // Read the peb loader data from the target process

                var pebLoaderData = memoryManager.ReadMemory<Structures.PebLdrData32>((IntPtr) peb.Ldr);

                var currentEntry = pebLoaderData.InLoadOrderModuleList.Flink;

                var lastEntry = pebLoaderData.InLoadOrderModuleList.Blink;

                while (true)
                {
                    // Read the current list entry from the InLoadOrder linked list

                    var dllEntry = memoryManager.ReadMemory<Structures.LdrDataTableEntry32>((IntPtr) currentEntry);

                    var dllPathBytes = memoryManager.ReadMemory((IntPtr) dllEntry.FullDllName.Buffer, dllEntry.FullDllName.Length);

                    var dllPath = Encoding.Default.GetString(dllPathBytes).Replace("\0", "");

                    if (dllPath.Equals(PropertyWrapper.DllPath, StringComparison.OrdinalIgnoreCase))
                    {
                        // Unlink the entry from the InLoadOrder linked list

                        UnlinkEntryFromLinkedList(dllEntry.InLoadOrderLinks);

                        // Unlink the entry from the InMemoryOrder linked list

                        UnlinkEntryFromLinkedList(dllEntry.InMemoryOrderLinks);

                        // Unlink the entry from the InInitOrder linked list

                        UnlinkEntryFromLinkedList(dllEntry.InInitOrderLinks);

                        // Unlink the entry from the LdrpHashTable linked list

                        UnlinkEntryFromLinkedList(dllEntry.HashTableEntry);

                        // Write over the entry with 0's

                        memoryManager.WriteMemory((IntPtr) dllEntry.BaseDllName.Buffer, new byte[dllEntry.BaseDllName.MaximumLength]);

                        memoryManager.WriteMemory((IntPtr) dllEntry.FullDllName.Buffer, new byte[dllEntry.FullDllName.MaximumLength]);

                        memoryManager.WriteMemory((IntPtr) currentEntry, new byte[Marshal.SizeOf<Structures.LdrDataTableEntry32>()]);

                        break;
                    }

                    if (currentEntry == lastEntry)
                    {
                        var dllName = Path.GetFileName(PropertyWrapper.DllPath);

                        throw new ArgumentException($"No DLL with the name {dllName} was found in the process environment block");
                    }

                    // Get the address of the next entry in the InLoadOrder linked list

                    currentEntry = dllEntry.InLoadOrderLinks.Flink;
                }

                // Free the memory allocated for the buffer

                MemoryTools.FreeMemoryForBuffer(pebBaseAddressBuffer, sizeof(ulong));
            }

            else
            {
                // Query the target process for the information about the process

                var pbiBuffer = (IntPtr) PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtQueryInformationProcess>(PropertyWrapper.ProcessHandle.Value, Enumerations.ProcessInformationClass.BasicInformation);

                // Marshal the process information from the buffer

                var pbi = Marshal.PtrToStructure<Structures.ProcessBasicInformation>(pbiBuffer);

                // Read the peb from the target process

                var peb = memoryManager.ReadMemory<Structures.Peb64>(pbi.PebBaseAddress);

                // Read the peb loader data from the target process

                var pebLoaderData = memoryManager.ReadMemory<Structures.PebLdrData64>((IntPtr) peb.Ldr);

                var currentEntry = pebLoaderData.InLoadOrderModuleList.Flink;

                var lastEntry = pebLoaderData.InLoadOrderModuleList.Blink;

                while (true)
                {
                    // Read the current list entry from the InLoadOrder linked list

                    var dllEntry = memoryManager.ReadMemory<Structures.LdrDataTableEntry64>((IntPtr) currentEntry);

                    var dllPathBytes = memoryManager.ReadMemory((IntPtr) dllEntry.FullDllName.Buffer, dllEntry.FullDllName.Length);

                    var dllPath = Encoding.Default.GetString(dllPathBytes).Replace("\0", "");

                    if (dllPath.Equals(PropertyWrapper.DllPath, StringComparison.OrdinalIgnoreCase))
                    {
                        // Unlink the entry from the InLoadOrder linked list

                        UnlinkEntryFromLinkedList(dllEntry.InLoadOrderLinks);

                        // Unlink the entry from the InMemoryOrder linked list

                        UnlinkEntryFromLinkedList(dllEntry.InMemoryOrderLinks);

                        // Unlink the entry from the InInitOrder linked list

                        UnlinkEntryFromLinkedList(dllEntry.InInitOrderLinks);

                        // Unlink the entry from the LdrpHashTable linked list

                        UnlinkEntryFromLinkedList(dllEntry.HashTableEntry);

                        // Write over the entry with 0's

                        memoryManager.WriteMemory((IntPtr) dllEntry.BaseDllName.Buffer, new byte[dllEntry.BaseDllName.MaximumLength]);

                        memoryManager.WriteMemory((IntPtr) dllEntry.FullDllName.Buffer, new byte[dllEntry.FullDllName.MaximumLength]);

                        memoryManager.WriteMemory((IntPtr) currentEntry, new byte[Marshal.SizeOf<Structures.LdrDataTableEntry64>()]);

                        break;
                    }

                    if (currentEntry == lastEntry)
                    {
                        var dllName = Path.GetFileName(PropertyWrapper.DllPath);

                        throw new ArgumentException($"No DLL with the name {dllName} was found in the process environment block");
                    }

                    // Get the address of the next entry in the InLoadOrder linked list

                    currentEntry = dllEntry.InLoadOrderLinks.Flink;
                }

                // Free the memory allocated for the buffer

                MemoryTools.FreeMemoryForBuffer(pbiBuffer, Marshal.SizeOf<Structures.ProcessBasicInformation>());
            }

            return true;
        }

        private void UnlinkEntryFromLinkedList(Structures.ListEntry32 listEntry)
        {
            var memoryManager = PropertyWrapper.MemoryManager.Value;

            // Read the previous list entry from the linked list

            var previousListEntry = memoryManager.ReadMemory<Structures.ListEntry32>((IntPtr) listEntry.Blink);

            // Change the front link of the previous list entry to the front link of the list entry

            previousListEntry.Flink = listEntry.Flink;

            // Write over the back link of the list entry with the previous list entry

            memoryManager.WriteMemory((IntPtr) listEntry.Blink, previousListEntry);

            // Read the next list entry from the linked list

            var nextListEntry = memoryManager.ReadMemory<Structures.ListEntry32>((IntPtr) listEntry.Flink);

            // Change the back link of the next list entry to the back link of the list entry

            nextListEntry.Blink = listEntry.Blink;

            // Write over the front link of the list entry with the next entry

            memoryManager.WriteMemory((IntPtr) listEntry.Flink, nextListEntry);

        }

        private void UnlinkEntryFromLinkedList(Structures.ListEntry64 listEntry)
        {
            var memoryManager = PropertyWrapper.MemoryManager.Value;

            // Read the previous list entry from the linked list

            var previousListEntry = memoryManager.ReadMemory<Structures.ListEntry64>((IntPtr) listEntry.Blink);

            // Change the front link of the previous list entry to the front link of the list entry

            previousListEntry.Flink = listEntry.Flink;

            // Write over the back link of the list entry with the previous list entry

            memoryManager.WriteMemory((IntPtr) listEntry.Blink, previousListEntry);

            // Read the next list entry from the linked list

            var nextListEntry = memoryManager.ReadMemory<Structures.ListEntry64>((IntPtr) listEntry.Flink);

            // Change the back link of the next list entry to the back link of the list entry

            nextListEntry.Blink = listEntry.Blink;

            // Write over the front link of the list entry with the next entry

            memoryManager.WriteMemory((IntPtr) listEntry.Flink, nextListEntry);
        }
    }
}
