namespace Security.Server.Hashing
{
    using System.Runtime.InteropServices;

    public class Libsodium
    {
        private const string Name = "libsodium";

        static Libsodium()
        {
            sodium_init();
        }

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_init();

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void randombytes_buf(byte[] buffer, int size);

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str(byte[] buffer, string password, long passwordLength,
            ulong opsLimit,
            uint memLimit);

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_verify(string password, string hashedPassword, long passwordLength);

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_str_needs_rehash(string password, ulong opsLimit, uint memLimit);

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint crypto_pwhash_strbytes();

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong crypto_pwhash_opslimit_moderate();

        [DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint crypto_pwhash_memlimit_moderate();
    }
}
