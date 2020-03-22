using System.Threading.Tasks;
using System.Security.Cryptography;
using CipherService.Services.Interfaces;
using Microsoft.AspNetCore.DataProtection;
using System.Text;
using System.IO;
using System;

namespace CipherService
{
    public class Cipher : ICipherService
    {
        private const string _KEY = "5134567890tHiSsh0rTk3y1234551298";

        public Cipher()
        {
        }

        public string Encrypt(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return string.Empty;
            }

            byte[] key = Encoding.UTF8.GetBytes(_KEY);

            using (var alg = Aes.Create())
            {
                using (var cipher = alg.CreateEncryptor(key, alg.IV))
                {
                    using (var memStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memStream, cipher, CryptoStreamMode.Write))
                        {
                            using (var swEcrypt = new StreamWriter(cryptoStream))
                            { 
                                swEcrypt.Write(input);
                            }

                            var iv = alg.IV;
                            var decipheredContent = memStream.ToArray();
                            var result = new byte[iv.Length + decipheredContent.Length];

                            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                            Buffer.BlockCopy(decipheredContent, 0, result, iv.Length, decipheredContent.Length);

                            var str = Convert.ToBase64String(result);
                            var fullCipher = Convert.FromBase64String(str);

                            return str;
                        }
                    }
                }
            }
        }
        public string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
            {
                return string.Empty;
            }

            var fullCipher = Convert.FromBase64String(cipherText);

            var iv = new byte[16];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, fullCipher.Length - iv.Length);

            var key = Encoding.UTF8.GetBytes(_KEY);

            using (var aesAlg = Aes.Create())
            {
                using (var decryptor = aesAlg.CreateDecryptor(key, iv))
                {
                    string result;
                    using (var memStream = new MemoryStream(cipher))
                    {
                        using (var cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(cryptoStream))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                    return result;
                }
            }
        }
        public async Task<string> EncryptAsync(string input)
        {
            return await Task.FromResult(this.Encrypt(input));
        }
        public async Task<string> DecryptAsync(string cipheredText)
        {
            return await Task.FromResult(this.Decrypt(cipheredText));
        }
    }
}
