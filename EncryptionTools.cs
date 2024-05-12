using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AlvinSoft.Cryptography {

    /// <summary>
    /// Thread-safe class for generating random sequences of bytes and numbers
    /// </summary>
    public static class RandomGenerator {
        internal static readonly object Sync = new object();
        internal static readonly Random Random = new Random();
        public static int Next() {
            lock (Sync) {
                return Random.Next();
            }
        }

        public static int Next(int minInclusive, int maxExclusive) {
            lock (Sync) {
                return Random.Next(minInclusive, maxExclusive);
            }
        }

        public static void FillNonZeroBytes(byte[] arrayToFill) {
            lock (Sync) {
                Random.NextBytes(arrayToFill);
            }
        }
        public static byte[] GenerateBytes(int size) {
            byte[] buffer = new byte[size];
            FillNonZeroBytes(buffer);
            return buffer;
        }
    }

    public class AesEncryption : IDisposable {

        public byte[] Key { get; private set; }
        public byte[] IV { get; private set; }
        public byte[] Salt { get; private set; }
        private string _password;
        public string Password {
            get => _password;
            set {
                _password = value;
                if (Salt != null)
                    Key = DeriveKey(Password, Salt, KeyDeriveIterations);
            }
        }

        public int SaltSize { get; } = 32;
        public const int DefaultKeyDeriveIterations = 696;
        public int KeyDeriveIterations { get; } = DefaultKeyDeriveIterations;
        /// <summary>Only relevant if used to generate a new password</summary>
        public int GenPasswordLength { get; } = 10;
        public bool NumbersOnlyPassword { get; } = false;

        private readonly object Sync = new object();

        /// <summary>Generates new password, salt, IV then derives the key (in this order) based on this instance's generation properties</summary>
        public void GenerateAndFill() {

            _password = NumbersOnlyPassword ? GenerateNumberPassword(GenPasswordLength) : GeneratePassword(GenPasswordLength);
            Salt = RandomGenerator.GenerateBytes(SaltSize);
            IV = GenerateIv();
            Key = DeriveKey(Password, Salt, KeyDeriveIterations);
        }

        /// <summary>Creates a new instance and calls <c>GenerateAndFill()</c></summary>
        public AesEncryption() => GenerateAndFill();

        /// <summary>Create a new instance, assign password, salt and iv, then derive the key</summary>
        public AesEncryption(string password, byte[] iv, byte[] salt, int derivingIterations = DefaultKeyDeriveIterations) {
            Password = password;
            IV = new byte[iv.Length];
            Salt = new byte[salt.Length];
            Array.Copy(iv, IV, IV.Length);
            Array.Copy(salt, Salt, Salt.Length);
            Key = DeriveKey(Password, Salt, KeyDeriveIterations);
            NumbersOnlyPassword = Encoding.ASCII.GetBytes(password).All(k => 0x0030 <= k && k <= 0x0039); //use ascii so one byte equals one character
        }

        #region Encrypt
        ///<summary>Encrypts a unicode string using the instance's cryptographic info</summary>
        ///<returns>The encrypted bytes. If the encryption fails, <c>null</c></returns>
        public byte[] EncryptString(string data) {

            lock (Sync) {
                using (var aes = Aes.Create()) {

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
        }
        ///<summary>Encrypts the bytes using the instance's cryptographic info</summary>
        ///<returns>The encrypted bytes. If the encryption fails, <c>null</c></returns>
        public byte[] EncryptBytes(byte[] data) {
            lock (Sync) {
                using (var aes = Aes.Create()) {

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
                using (var aes = Aes.Create()) {

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
        }
        ///<summary>Decrypts the bytes using the instance's cryptographic info</summary>
        ///<returns>The decrypted bytes. If the decryption fails, <c>null</c></returns>
        public byte[] DecryptBytes(byte[] data) {
            lock (Sync) {
                using (var aes = Aes.Create()) {

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
        }

        /// <summary>Create a write-mode encryptor stream using the instance's cryptographic info</summary>
        /// <param name="target">The target stream that the CryptoStream writes to</param>
        /// <remarks>Make sure to call <c>Dispose()</c> on the stream when no longer needed</remarks>
        public CryptoStream GetEncryptor(Stream target) {
            lock (Sync) {
                using (var aes = Aes.Create()) {

                    aes.Key = Key;
                    aes.IV = IV;

                    return new CryptoStream(target, aes.CreateEncryptor(), CryptoStreamMode.Write);
                }
            }
        }

        /// <summary>Create a read-mode encryptor stream using the instance's cryptographic info</summary>
        /// <param name="target">The target stream that the CryptoStream writes to</param>
        /// <remarks>Make sure to call <c>Dispose()</c> on the stream when no longer needed</remarks>
        public CryptoStream GetDecryptor(Stream target) {
            lock (Sync) {
                using (var aes = Aes.Create()) {
                    aes.Key = Key;
                    aes.IV = IV;

                    return new CryptoStream(target, aes.CreateDecryptor(), CryptoStreamMode.Read);
                }
            }
        }
        #endregion

        /// <summary>Generate a string consisting of <paramref name="length"/> numbers</summary>
        public static string GenerateNumberPassword(int length) {

            var sb = new StringBuilder(length);
            for (int i = 0; i < length; i++)
                sb.Append(RandomGenerator.Next(0, 10).ToString());
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
        public static byte[] GenerateIv() {
            using (var aes = Aes.Create()) {
                aes.GenerateKey();
                aes.GenerateIV();
                byte[] iv = new byte[aes.IV.Length];
                Array.Copy(aes.IV, iv, iv.Length);
                return iv;
            }
        }
        public static byte[] DeriveKey(string code, byte[] salt, int iterations) {

            if (code == null)
                throw new ArgumentNullException(nameof(code));
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));
            if (iterations < 0)
                throw new ArgumentOutOfRangeException(nameof(iterations));

            var gen = new Rfc2898DeriveBytes(code, salt, iterations);
            return gen.GetBytes(32);
        }


        public override string ToString() => "Code: " + Password + " Key: " + Convert.ToBase64String(Key) + " IV: " + Convert.ToBase64String(IV) + " Salt: " + Convert.ToBase64String(Salt);

        public void Dispose() {
            IV = null;
            Key = null;
            Salt = null;
            Password = null;
        }
    }

    public class RsaEncryption : IDisposable {
        public const int RSAKeySize = 2048;
        private readonly RSACryptoServiceProvider rsa;
        public bool HasPrivateKey { get; }
        public bool HasPublicKey { get; }

        /// <summary>Create a new RSA instance and generate keys</summary>
        public RsaEncryption() {
            rsa = new RSACryptoServiceProvider(RSAKeySize);
            HasPrivateKey = true;
            HasPublicKey = true;
        }

        /// <summary>Create a new RSA instance and import <paramref name="parameters"/></summary>
        public RsaEncryption(RSAParameters parameters) {
            rsa = new RSACryptoServiceProvider(RSAKeySize);
            rsa.ImportParameters(parameters);

            if (rsa.PublicOnly) {
                HasPrivateKey = false;
                HasPublicKey = true;
            } else {
                HasPrivateKey = true;
                HasPublicKey = true;
            }
        }

        /// <summary>Create a new RSA instance and import the provided public key values
        public RsaEncryption(byte[] publicKeyModulus, byte[] publicKeyExponent) {

            byte[] mod = new byte[publicKeyModulus.Length];
            byte[] exp = new byte[publicKeyExponent.Length];
            Array.Copy(publicKeyModulus, mod, mod.Length);
            Array.Copy(publicKeyExponent, exp, exp.Length);

            RSAParameters publicKey = new RSAParameters() {
                Modulus = mod,
                Exponent = exp
            };
            rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(publicKey);

            HasPublicKey = true;
            HasPrivateKey = false;
        }

        /// <summary>Returns all RSA parameters, including this instance's private key. Use with caution!</summary>
        public RSAParameters GetPrivateKey() => rsa.ExportParameters(true);
        /// <summary>Returns the RSA parameters containing this instance's public key only.</summary>
        public RSAParameters GetPublicKey() => rsa.ExportParameters(false);

        /// <summary>Encrypt <paramref name="data"/> using this instance's public key</summary>
        /// /// <returns>The encrypted bytes. If anything fails, <c>null</c>.</returns>
        public byte[] EncryptBytes(byte[] data) {
            try {
                return rsa.Encrypt(data, true);
            } catch {
                return null;
            }
        }

        /// <summary>Decrypt <paramref name="data"/> using this instance's private key</summary>
        /// <returns>The encrypted bytes. If anything fails, <c>null</c>.</returns>
        /// <exception cref="CryptographicException"/>
        public byte[] DecryptBytes(byte[] data) {
            if (!HasPrivateKey)
                throw new CryptographicException("You need the private key to decrypt data");

            try {
                return rsa.Decrypt(data, true);
            } catch {
                return null;
            }
        }

        /// <summary>Encrypt unicode string <paramref name="data"/> using this instance's public key</summary>
        /// <returns>The encrypted bytes. If anything fails, <c>null</c>.</returns>
        public byte[] EncryptString(string data) {
            try {
                return rsa.Encrypt(Encoding.Unicode.GetBytes(data), true);
            } catch {
                return null;
            }
        }

        /// <summary>Decrypt encrypted unicode string bytes <paramref name="encryptedData"/> using this instance's private key</summary>
        /// <returns>The encrypted bytes. If anything fails, <c>null</c>.</returns>
        /// <exception cref="CryptographicException"/>
        public string DecryptString(byte[] encryptedData) {
            if (!HasPrivateKey)
                throw new CryptographicException("You need the private key to decrypt data");

            try {
                return Encoding.Unicode.GetString(rsa.Decrypt(encryptedData, true));
            } catch {
                return null;
            }
        }

        public void Dispose() => rsa.Dispose();
    }
}
