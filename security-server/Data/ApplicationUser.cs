namespace Security.Server.Data
{
    using Microsoft.AspNetCore.Identity;

    public class ApplicationUser : IdentityUser
    {
        public byte[] PhoneEncrypted { get; set; }
    }
}
