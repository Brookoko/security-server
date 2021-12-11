namespace Security.Server.Data
{
    using System;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.DataProtection.KeyManagement;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

    public class UserStore<TUser> : UserOnlyStore<TUser> where TUser : IdentityUser, new()
    {
        private readonly IKeyManager keyManager;

        public UserStore(IKeyManager keyManager, ApplicationDbContext context,
            IdentityErrorDescriber describer = null) : base(
            context, describer)
        {
            this.keyManager = keyManager;
        }

        public override async Task<string> GetPhoneNumberAsync(TUser user,
            CancellationToken cancellationToken = new())
        {
            var phoneNumber = await base.GetPhoneNumberAsync(user, cancellationToken);
            if (string.IsNullOrEmpty(phoneNumber))
            {
                return phoneNumber;
            }
            var key = GetKey();
            var encryptor = key.CreateEncryptor();
            var phoneBytes = GetBytes(phoneNumber);
            var phoneNumberBytes = encryptor.Decrypt(phoneBytes, ArraySegment<byte>.Empty);
            return Encoding.UTF8.GetString(phoneNumberBytes);
        }

        public override async Task SetPhoneNumberAsync(TUser user, string phoneNumber,
            CancellationToken cancellationToken = new())
        {
            if (string.IsNullOrEmpty(phoneNumber))
            {
                await base.SetPhoneNumberAsync(user, phoneNumber, cancellationToken);
                return;
            }
            var key = GetKey();
            var encryptor = key.CreateEncryptor();
            var data = Encoding.UTF8.GetBytes(phoneNumber);
            var phoneNumberBytes = encryptor.Encrypt(data, ArraySegment<byte>.Empty);
            var encryptedPhoneNumber = GetString(phoneNumberBytes);
            await base.SetPhoneNumberAsync(user, encryptedPhoneNumber, cancellationToken);
        }

        private IKey GetKey()
        {
            return keyManager.GetAllKeys().First();
        }

        private byte[] GetBytes(string text)
        {
            return Enumerable.Range(0, text.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(text.Substring(x, 2), 16))
                .ToArray();
        }

        private string GetString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }
    }
}
