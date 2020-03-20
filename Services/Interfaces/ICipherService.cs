using System.Threading.Tasks;

namespace CipherService.Services.Interfaces
{
    public interface ICipherService
    {
        string Encrypt(string input);
        string Decrypt(string input);
        Task<string> EncryptAsync(string input);
        Task<string> DecryptAsync(string input);
    }
}
