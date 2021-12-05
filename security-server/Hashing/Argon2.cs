namespace Security.Server.Hashing
{
    using System;
    using System.Linq;
    using System.Text;

    public class Argon2
    {
        public string HashPassword(string password)
        {
            var hash = new byte[Libsodium.crypto_pwhash_strbytes()];
            var result = Libsodium.crypto_pwhash_str(hash, password, password.Length,
                Libsodium.crypto_pwhash_opslimit_moderate(),
                Libsodium.crypto_pwhash_memlimit_moderate());

            if (result != 0)
            {
                throw new Exception("An unexpected error has occurred while hashing password");
            }

            var str = Encoding.UTF8.GetString(hash.Where(b => b != 0).ToArray());
            Console.WriteLine($"{str}");
            return str;
        }

        public bool Verify(string hashedPassword, string providedPassword)
        {
            var result = Libsodium.crypto_pwhash_str_verify(hashedPassword, providedPassword, providedPassword.Length);
            return result == 0;
        }

        public bool IsRehashNeeded(string hashedPassword)
        {
            var result = Libsodium.crypto_pwhash_str_needs_rehash(hashedPassword,
                Libsodium.crypto_pwhash_opslimit_moderate(),
                Libsodium.crypto_pwhash_memlimit_moderate());
            return result == 1;
        }
    }
}
