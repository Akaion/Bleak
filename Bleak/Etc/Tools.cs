using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static Bleak.Etc.Native;

namespace Bleak.Etc
{
    internal static class Tools
    {
        internal static async void AsyncWait(int milliseconds)
        {
            await Task.Delay(milliseconds);
        }
        
        
        internal static TStructure PointerToStructure<TStructure>(IntPtr address)
        {
            // Read the structure from the memory at the address
            
            var structure = (TStructure) Marshal.PtrToStructure(address, typeof(TStructure));

            return structure;
        }     
        
        internal static IntPtr RvaToVa(IntPtr baseAddress, int eLfanew, IntPtr rva)
        {
            // Convert a relative virtual address to a virtual address

            return ImageRvaToVa(baseAddress + eLfanew, baseAddress, rva, IntPtr.Zero);
        }
        
        internal static byte[] StructureToBytes<TStructure>(TStructure structure)
        {
            // Get the size of the structure
            
            var size = Marshal.SizeOf(structure);

            // Create an array to store the bytes of the structure            
            
            var structureBytes = new byte[size];

            // Allocate memory for a buffer to store the structure
            
            var buffer = Marshal.AllocHGlobal(size);
            
            // Store the structure in the buffer
            
            Marshal.StructureToPtr(structure, buffer, true);
            
            // Copy the structure from the buffer to the array
            
            Marshal.Copy(buffer, structureBytes, 0, size);
            
            // Free the memory previously allocated for the buffer
            
            Marshal.FreeHGlobal(buffer);

            return structureBytes;
        }
    }
}