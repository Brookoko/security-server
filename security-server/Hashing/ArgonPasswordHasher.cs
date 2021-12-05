namespace Security.Server.Hashing
{
    using Microsoft.AspNetCore.Identity;

    public class ArgonPasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
    {
        private readonly Argon2 argon = new();

        public string HashPassword(TUser user, string password)
        {
            return argon.HashPassword(password);
        }

        public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword,
            string providedPassword)
        {
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
    }
}
