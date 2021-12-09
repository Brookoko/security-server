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

    public class UserStore : UserOnlyStore<ApplicationUser>
    {
        private readonly IKeyManager keyManager;

        public UserStore(IKeyManager keyManager, ApplicationDbContext context,
            IdentityErrorDescriber describer = null) : base(
            context, describer)
        {
            this.keyManager = keyManager;
        }

        public override async Task<string> GetPhoneNumberAsync(ApplicationUser user,
            CancellationToken cancellationToken = new())
        {
            var phoneBytes = user.PhoneEncrypted;
            if (phoneBytes == null || phoneBytes.Length == 0)
            {
                return "";
            }
            var key = GetKey();
            var encryptor = key.CreateEncryptor();
            var phoneNumberBytes = encryptor.Decrypt(phoneBytes, ArraySegment<byte>.Empty);
            return Encoding.UTF8.GetString(phoneNumberBytes);
        }

        public override async Task SetPhoneNumberAsync(ApplicationUser user, string phoneNumber,
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
            user.PhoneEncrypted = phoneNumberBytes;
        }

        private IKey GetKey()
        {
            return keyManager.GetAllKeys().First();
        }
    }
}
