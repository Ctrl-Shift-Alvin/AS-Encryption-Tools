using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AlvinSoft.Cryptography {

    /// <summary>Represents the Key and IV of an Aes encryption. Optionally holds a password and a salt to derive the key from.</summary>
    public class AesEncryption : IDisposable {

        /// <summary>The Aes key bytes</summary>
        public byte[] Key { get; private set; }
        /// <summary>The initialization vector bytes</summary>
        public byte[] IV { get; private set; }
        /// <summary>The salt bytes used to derive the <c>Key</c> using <c>Password</c></summary>
        public byte[] Salt { get; private set; }
        private string _password;
        /// <summary>The password used in combination with <c>Salt</c></summary>
        public string Password {
            get => _password;
            set {
                _password = value;
                if (Salt != null)
                    Key = DeriveKey(Password, Salt, KeyDeriveIterations);
            }
        }
        /// <summary>Shorthand for <c>Password == null</c></summary>
        public bool HasPassword => Password == null;

        /// <summary>The length of the salt used to generate the salt next time</summary>
        public int SaltSize { get; } = 32;
        /// <summary>The default number assigned to <see cref="KeyDeriveIterations"/></summary>
        public const int DefaultKeyDeriveIterations = 696;
        /// <summary>The number of iterations used to derive the key using the password</summary>
        /// <remarks>Only relevant for the next password generation</remarks>
        public int KeyDeriveIterations { get; set; } = DefaultKeyDeriveIterations;
        /// <summary>The length of the password</summary>
        /// <remarks>Assigning a password sets this variable accordingly. Used for password generation.</remarks>
        public int PasswordLength { get; set; } = 10;
        /// <summary>Set to <c>true</c> to generate a password consisting of numbers only</summary>
        /// <remarks>Assigning a password sets this variable accordingly. Used for password generation.</remarks>
        public bool NumbersOnlyPassword { get; } = false;

        private readonly object Sync = new();

        /// <summary>Generates new password, salt, IV then derives the key (in this order) based on this instance's generation properties</summary>
        public void GenerateAndFill() {

            _password = NumbersOnlyPassword ? GenerateNumberPassword(PasswordLength) : GeneratePassword(PasswordLength);
            Salt = RandomGenerator.GenerateBytes(SaltSize);
            IV = GenerateIv();
            Key = DeriveKey(Password, Salt, KeyDeriveIterations);
        }

        /// <summary>Creates a new instance and calls <c>GenerateAndFill()</c></summary>
        public AesEncryption() => GenerateAndFill();

        /// <summary>Create a new instance, assign password, salt and iv, then derive the key</summary>
        public AesEncryption(string password, byte[] salt, byte[] iv, int derivingIterations = DefaultKeyDeriveIterations) {
            Password = password;
            IV = new byte[iv.Length];
            Salt = new byte[salt.Length];
            Array.Copy(iv, IV, IV.Length);
            Array.Copy(salt, Salt, Salt.Length);
            Key = DeriveKey(Password, Salt, KeyDeriveIterations);
            PasswordLength = Password.Length;
            NumbersOnlyPassword = Encoding.ASCII.GetBytes(password).All(k => 0x0030 <= k && k <= 0x0039); //use ascii so one byte equals one character
        }
        /// <summary>Create a new instance and assign key and iv</summary>
        public AesEncryption(byte[] key, byte[] iv) {
            Key = key;
            IV = iv;
            Salt = null;
            Password = null;
        }

        #region Encrypt
        ///<summary>Encrypts a unicode string using the instance's cryptographic info</summary>
        ///<returns>The encrypted bytes. If the encryption fails, <c>null</c></returns>
        public byte[] EncryptString(string data) {

            lock (Sync) {
                using var aes = Aes.Create();

                aes.Key = Key;
                aes.IV = IV;

                byte[] encrypted;
                using (var outputStream = new MemoryStream()) {
                    using (var encryptorStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write)) {
                        using (var inputStream = new StreamWriter(encryptorStream, Encoding.Unicode)) {
                            try {
                                inputStream.Write(data);
                            } catch {
                                return null;
                            }
                        }
                        encrypted = outputStream.ToArray();
                    }
                }

                return encrypted;
            }
        }
        ///<summary>Encrypts the bytes using the instance's cryptographic info</summary>
        ///<returns>The encrypted bytes. If the encryption fails, <c>null</c></returns>
        public byte[] EncryptBytes(byte[] data) {

            lock (Sync) {

                using var aes = Aes.Create();

                aes.Key = Key;
                aes.IV = IV;

                byte[] encrypted;
                using (var outputStream = new MemoryStream()) {
                    using (var encryptorStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write)) {
                        try {
                            encryptorStream.Write(data, 0, data.Length);
                        } catch {
                            return null;
                        }
                    }
                    encrypted = outputStream.ToArray();
                }

                return encrypted;
            }
        }
        #endregion
        #region Base64
        ///<summary>Encrypts a string using the instance's cryptographic info</summary>
        ///<returns>The encrypted string bytes as a Base64 string</returns>
        public string EncryptToBase64(string data) {
            var encrypted = EncryptString(data);
            if (encrypted != null)
                return Convert.ToBase64String(encrypted);

            return null;
        }
        ///<summary>Decrypts Base64 string bytes using the instance's cryptographic info</summary>
        public string DecryptBase64(string data) {
            if (data != null)
                DecryptString(Convert.FromBase64String(data));

            return null;
        }
        #endregion
        #region Decrypt
        ///<summary>Decrypts unicode bytes using the instance's cryptographic info</summary>
        ///<returns>The decrypted bytes. If the decryption fails, <c>null</c></returns>
        public string DecryptString(byte[] data) {

            lock (Sync) {

                using var aes = Aes.Create();

                aes.Key = Key;
                aes.IV = IV;

                string decrypted;
                using (var inputStream = new MemoryStream(data)) {
                    using (var decryptorStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read)) {
                        using (var outputStream = new StreamReader(decryptorStream, Encoding.Unicode)) {

                            try {
                                decrypted = outputStream.ReadToEnd();
                            } catch {
                                return null;
                            }

                        }
                    }
                }

                return decrypted;
            }
        }
        ///<summary>Decrypts the bytes using the instance's cryptographic info</summary>
        ///<returns>The decrypted bytes. If the decryption fails, <c>null</c></returns>
        public byte[] DecryptBytes(byte[] data) {

            lock (Sync) {

                using var aes = Aes.Create();

                aes.Key = Key;
                aes.IV = IV;

                byte[] decrypted;
                using (var inputStream = new MemoryStream(data)) {
                    using (var decryptorStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read)) {
                        using (var outputStream = new MemoryStream()) {

                            try {
                                decryptorStream.CopyTo(outputStream);
                            } catch {
                                return null;
                            }

                            decrypted = outputStream.ToArray();
                        }
                    }
                }

                return decrypted;
            }
        }

        /// <summary>Create a write-mode encryptor stream using the instance's cryptographic info</summary>
        /// <param name="target">The target stream that the CryptoStream writes to</param>
        /// <remarks>Make sure to call <c>Dispose()</c> on the stream when no longer needed</remarks>
        public CryptoStream GetEncryptor(Stream target) {

            lock (Sync) {

                using var aes = Aes.Create();

                aes.Key = Key;
                aes.IV = IV;

                return new CryptoStream(target, aes.CreateEncryptor(), CryptoStreamMode.Write);
            }
        }

        /// <summary>Create a read-mode encryptor stream using the instance's cryptographic info</summary>
        /// <param name="target">The target stream that the CryptoStream writes to</param>
        /// <remarks>Make sure to call <c>Dispose()</c> on the stream when no longer needed</remarks>
        public CryptoStream GetDecryptor(Stream target) {
            lock (Sync) {
                using var aes = Aes.Create();
                aes.Key = Key;
                aes.IV = IV;

                return new CryptoStream(target, aes.CreateDecryptor(), CryptoStreamMode.Read);
            }
        }
        #endregion

        /// <summary>Generate a string consisting of <paramref name="length"/> numbers</summary>
        public static string GenerateNumberPassword(int length) {

            var sb = new StringBuilder(length);
            for (int i = 0; i < length; i++)
                sb.Append(RandomGenerator.Next(0, 10));
            return sb.ToString();

        }

        /// <summary>Generate a random combination string of the most common characters</summary>
        public static string GeneratePassword(int length) {

            char[] validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?!@#$%^&*()_+-={}[];\'\"\\,./<>\\|`~".ToCharArray();
            var sb = new StringBuilder(length);
            for (int i = 0; i < length; i++)
                sb.Append(validChars[RandomGenerator.Next(0, validChars.Length)]);
            return sb.ToString();

        }
        /// <summary>Creates an <see cref="Aes"/> instance, an returns a copy of its IV</summary>
        public static byte[] GenerateIv() {
            using var aes = Aes.Create();

            aes.GenerateKey();
            aes.GenerateIV();
            byte[] iv = new byte[aes.IV.Length];
            Array.Copy(aes.IV, iv, iv.Length);

            return iv;
        }
        /// <summary>Derives a password using a salt, and iterates <paramref name="iterations"/> times</summary>
        /// <param name="password">The password string</param>
        /// <param name="salt">The salt bytes</param>
        /// <param name="iterations">The iteration count</param>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public static byte[] DeriveKey(string password, byte[] salt, int iterations) {

            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNull(salt);
            ArgumentOutOfRangeException.ThrowIfNegative(iterations);

            var gen = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA512);
            return gen.GetBytes(32);
        }

        /// <summary>Disposes of this instance</summary>
        public void Dispose() {
            IV = null;
            Key = null;
            Salt = null;
            Password = null;
            GC.SuppressFinalize(this);
        }
    }

    
}
