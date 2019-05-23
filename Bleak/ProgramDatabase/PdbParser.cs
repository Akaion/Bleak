using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Bleak.Native;
using Bleak.PortableExecutable;
using Bleak.PortableExecutable.Objects;
using Bleak.ProgramDatabase.Objects;
using Bleak.Shared;

namespace Bleak.ProgramDatabase
{
    internal class PdbParser 
    {
        internal bool PdbDownloaded;

        internal readonly List<Symbol> PdbSymbols;

        private string _pdbPath;
        
        internal PdbParser(bool isWow64)
        {
            var systemFolderPath = isWow64
                                 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
                                 : Environment.GetFolderPath(Environment.SpecialFolder.System);

            var pdbPath = Path.Combine(systemFolderPath, "ntdll.dll");
            
            using (var peParser = new PeParser(pdbPath))
            {
                PdbSymbols = GetPdbSymbols(peParser.GetDebugData()).Result;
            }
        }
        
        private Task DownloadPdb(DebugData pdbDebugData)
        {
            // Get the URI for the PDB
            
            var pdbUri = "http://msdl.microsoft.com/download/symbols/" + pdbDebugData.Name + "/" + pdbDebugData.Guid + pdbDebugData.Age + "/" + pdbDebugData.Name;

            // Ensure a temporary directory exists on disk for the PDB

            var temporaryDirectoryInfo = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Bleak", "PDB"));

            var pdbName = $"ntdll-{pdbDebugData.Guid}-{pdbDebugData.Age}.pdb";

            _pdbPath = Path.Combine(temporaryDirectoryInfo.FullName, pdbName);

            // Ensure the PDB hasn't already been downloaded
            
            if (temporaryDirectoryInfo.EnumerateFiles().Any(file => file.Name == pdbName))
            {
                PdbDownloaded = true;
                
                return Task.CompletedTask;
            }

            // Clear the directory

            foreach (var file in temporaryDirectoryInfo.GetFiles())
            {
                try
                {
                    file.Delete();
                }

                catch (Exception)
                {
                    // The file is currently open and cannot be safely deleted
                }
            }

            using (var webClient = new WebClient())
            {
                if (new Ping().Send("msdl.microsoft.com")?.Status != IPStatus.Success)
                {
                    throw new WebException("Failed to ping the Microsoft symbol server");
                }
                
                // Download the PDB

                webClient.DownloadFileCompleted += (sender, @event) => { PdbDownloaded = true; };
                
                return webClient.DownloadFileTaskAsync(new Uri(pdbUri), Path.Combine(temporaryDirectoryInfo.FullName, pdbName));
            }
        }
        
        private async Task<List<Symbol>> GetPdbSymbols(DebugData pdbDebugData)
        {
            var symbols = new List<Symbol>();
            
            // Ensure the latest version of the PDB is downloaded
            
            await DownloadPdb(pdbDebugData);
            
            // Store the bytes of the PDB in a buffer
            
            var pdbBufferHandle = GCHandle.Alloc(File.ReadAllBytes(_pdbPath), GCHandleType.Pinned);

            var pdbBuffer = pdbBufferHandle.AddrOfPinnedObject();
            
            // Read the PDB header

            var pdbHeader = Marshal.PtrToStructure<Structures.PdbHeader>(pdbBuffer);
            
            // Determine the amount of streams in the PDB

            var rootPageNumber = Marshal.PtrToStructure<uint>(pdbBuffer.AddOffset(pdbHeader.PageSize * pdbHeader.RootStreamPageNumberListNumber));

            var rootStream = Marshal.PtrToStructure<uint>(pdbBuffer.AddOffset(pdbHeader.PageSize * rootPageNumber));

            var streams = new List<List<uint>>();

            var pageNumber = 0;
            
            for (var streamIndex = 0; streamIndex < rootStream; streamIndex += 1)
            {
                // Read the size of the stream
                
                var streamSize = Marshal.PtrToStructure<uint>(pdbBuffer.AddOffset(pdbHeader.PageSize * rootPageNumber + sizeof(uint) + sizeof(uint) * streamIndex));

                // Calculate the amount of pages in the stream
                
                var pagesNeeded = streamSize / pdbHeader.PageSize;

                if (streamSize % pdbHeader.PageSize != 0)
                {
                    pagesNeeded += 1;
                }
                
                var streamPages = new List<uint>();

                for (var pageIndex = 0; pageIndex < pagesNeeded; pageIndex += 1)
                {
                    // Read the page of the stream

                    streamPages.Add(Marshal.PtrToStructure<uint>(pdbBuffer.AddOffset(pdbHeader.PageSize * rootPageNumber + sizeof(uint) + (rootStream + pageNumber) * sizeof(uint))));

                    pageNumber += 1;
                }
                
                streams.Add(streamPages); 
            }

            // Calculate the offset of the DBI stream
            
            var dbiStreamOffset = pdbHeader.PageSize * streams[3][0];

            // Read the DBI header

            var dbiHeader = Marshal.PtrToStructure<Structures.DbiHeader>(pdbBuffer.AddOffset(dbiStreamOffset));

            // Get the symbol stream

            var symbolStream = new byte[pdbHeader.PageSize * streams[dbiHeader.SymbolStreamIndex].Count];

            for (var pageIndex = 0; pageIndex < streams[dbiHeader.SymbolStreamIndex].Count; pageIndex += 1)
            {
                Marshal.Copy(pdbBuffer.AddOffset(pdbHeader.PageSize * streams[dbiHeader.SymbolStreamIndex][pageIndex]), symbolStream, (int) pdbHeader.PageSize * pageIndex, (int) pdbHeader.PageSize);
            }

            // Pin the symbol stream bytes
            
            var symbolStreamBufferHandle = GCHandle.Alloc(symbolStream, GCHandleType.Pinned);

            var symbolStreamBuffer = symbolStreamBufferHandle.AddrOfPinnedObject();

            while (true)
            {
                // Read the data of the symbol
                
                var symbolData = Marshal.PtrToStructure<Structures.SymbolData>(symbolStreamBuffer);
                
                if (symbolData.Magic != Constants.SymbolMagic)
                {
                    break;
                }

                // Read the name of the symbol
                
                var symbolName = Marshal.PtrToStringAnsi(symbolStreamBuffer.AddOffset(Marshal.SizeOf<Structures.SymbolData>()));
                
                symbols.Add(new Symbol(symbolName, symbolData.Offset, symbolData.Section));
                
                // Calculate the address of the next symbol
                
                symbolStreamBuffer += symbolData.Length + sizeof(ushort);
            }

            symbolStreamBufferHandle.Free();
            
            pdbBufferHandle.Free();

            return symbols;
        }
    }
}