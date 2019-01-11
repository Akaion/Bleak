using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

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

            return Native.ImageRvaToVa(baseAddress + eLfanew, baseAddress, rva, IntPtr.Zero);
        }
        
        internal static IntPtr StructureToPointer<TStructure>(TStructure structure)
        {
            // Get the size of the structure
            
            var structureSize = Marshal.SizeOf(typeof(TStructure));

            // Allocate memory to store the structure
            
            var pointer = Marshal.AllocHGlobal(structureSize);
            
            // Store the structure in memory
            
            Marshal.StructureToPtr(structure, pointer, true);

            return pointer;
        }
    }
}