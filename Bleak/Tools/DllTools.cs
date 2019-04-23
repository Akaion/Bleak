using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Bleak.Tools
{
    internal static class DllTools
    {
        internal static string CreateTemporaryDll(string dllName, byte[] dllBytes)
        {
            // Create a directory to store the temporary DLL

            var temporaryDirectoryInfo = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Bleak"));

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

            var temporaryDllPath = Path.Combine(temporaryDirectoryInfo.FullName, dllName);

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

        internal static string GenerateDllName(byte[] dllBytes)
        {
            // Hash the DLL bytes

            byte[] hashedDllBytes;

            using (var hashingService = new SHA256CryptoServiceProvider())
            {
                hashedDllBytes = hashingService.ComputeHash(dllBytes);
            }

            // Create a name for the DLL using a partial hash of the its bytes

            var stringBuilder = new StringBuilder();

            for (var index = 0; index < 14; index += 1)
            {
                stringBuilder.Append(hashedDllBytes[index].ToString("X2"));
            }

            return stringBuilder.Append(".dll").ToString();
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

            return stringBuilder.Append(".dll").ToString();
        }
    }
}
