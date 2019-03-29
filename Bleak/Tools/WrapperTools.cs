using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Bleak.Tools
{
    internal static class WrapperTools
    {
        internal static string CreateTemporaryDll(string dllName, byte[] dllBytes)
        {
            // Create a directory to store the temporary DLL

            var temporaryDllFolderPath = Path.Combine(Path.GetTempPath(), "Bleak");

            var temporaryDirectoryInfo = Directory.CreateDirectory(temporaryDllFolderPath);

            // Clear the directory

            foreach (var file in temporaryDirectoryInfo.GetFiles())
            {
                try
                {
                    file.Delete();
                }
                
                catch (Exception)
                {
                    // The DLL is currently loaded in a process and cannot be safely deleted
                }
            }

            // Create a temporary DLL

            var temporaryDllPath = Path.Combine(temporaryDllFolderPath, dllName);

            try
            {
                File.WriteAllBytes(temporaryDllPath, dllBytes);
            }

            catch (IOException)
            {
                // The DLL already exists and is loaded in a process and cannot be safely overwritten
            }

            return temporaryDllPath;
        }

        internal static string GenerateDllName(byte[] dllBytes)
        {
            // Hash the DLL bytes

            byte[] hashedDllBytes;

            using (var hashingService = new SHA256CryptoServiceProvider())
            {
                hashedDllBytes = hashingService.ComputeHash(dllBytes);
            }

            // Create a name for the DLL using a partial hash of the DLL bytes

            var stringBuilder = new StringBuilder();

            for (var index = 0; index < 14; index += 1)
            {
                stringBuilder.Append(hashedDllBytes[index].ToString("X2"));
            }

            return stringBuilder + ".dll";
        }

        internal static string GenerateRandomDllName()
        {
            var characterArray = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

            // Generate an array of random bytes

            var dllNameBytes = new byte[14];

            using (var rngService = new RNGCryptoServiceProvider())
            {
                rngService.GetBytes(dllNameBytes);
            }

            // Create a randomised name for the DLL

            var stringBuilder = new StringBuilder();

            foreach (var @byte in dllNameBytes)
            {
                stringBuilder.Append(characterArray[@byte % characterArray.Length]);
            }

            return stringBuilder + ".dll";
        }
    }
}
