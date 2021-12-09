namespace Security.Server.Hashing
{
    using System.Security.Cryptography;
    using System.Text;
    using Microsoft.AspNetCore.Identity;

    public class ArgonPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
    {
        private readonly Argon2 argon = new();
        private readonly SHA512 sha512 = new SHA512Managed();

        public string HashPassword(TUser user, string password)
        {
            return argon.HashPassword(password);
        }

        public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword,
            string providedPassword)
        {
            providedPassword = TruncatePassword(providedPassword);
            var isValid = argon.Verify(hashedPassword, providedPassword);
            if (!isValid)
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }
            var needRehash = argon.IsRehashNeeded(hashedPassword);
            if (needRehash)
            {
                return PasswordVerificationResult.SuccessRehashNeeded;
            }
            return PasswordVerificationResult.Success;
        }

        private string TruncatePassword(string providedPassword)
        {
            var data = Encoding.UTF8.GetBytes(providedPassword);
            var hash = sha512.ComputeHash(data);
            return Encoding.UTF8.GetString(hash);
        }
    }
}
