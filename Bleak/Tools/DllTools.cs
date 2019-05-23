using System;
using System.IO;

namespace Bleak.Tools
{
    internal static class DllTools
    {
        internal static string CreateTemporaryDll(byte[] dllBytes)
        {
            // Create a directory to store the temporary DLL

            var temporaryDirectoryInfo = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Bleak", "DLL"));

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

            // Create a temporary DLL

            var temporaryDllPath = Path.Combine(temporaryDirectoryInfo.FullName, Path.GetRandomFileName() + ".dll");

            try
            {
                File.WriteAllBytes(temporaryDllPath, dllBytes);
            }

            catch (IOException)
            {
                // A DLL already exists with the specified name and is loaded in a process and cannot be safely overwritten
            }

            return temporaryDllPath;
        }
    }
}