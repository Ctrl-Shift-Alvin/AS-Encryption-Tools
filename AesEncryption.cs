﻿using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace AlvinSoft.Cryptography {

    /// <summary>Represents a password securely stored in memory</summary>
    public class SecurePassword : IDisposable {
        /// <summary>The <see cref="System.Security.SecureString"/> instance that is storing the password</summary>
        public SecureString SecureString { get; private set; }

        /// <summary>The character password's length</summary>
        public int Length => SecureString.Length;

        /// <summary>Shorthand for <c>Length == 0</c></summary>
        public bool IsEmpty => Length == 0;

        /// <summary>Copies the password chars to a unicode string</summary>
        public string PasswordChars {
            get {
                IntPtr ptr = IntPtr.Zero;
                try {
                    ptr = SecureStringMarshal.SecureStringToGlobalAllocUnicode(SecureString);
                    return Marshal.PtrToStringUni(ptr);
                } finally {
                    Marshal.ZeroFreeGlobalAllocUnicode(ptr);
                }
            }
        }

        /// <summary>Returns the unicode bytes of the password. Shorthand for <c>Encoding.Unicode.GetBytes(PasswordChars)</c>.</summary>
        public byte[] PasswordUnicodeBytes => Encoding.Unicode.GetBytes(PasswordChars);

        /// <summary>Append <paramref name="c"/> to this password</summary>
        public void AppendChar(char c) => SecureString.AppendChar(c);

        /// <summary>Append <paramref name="s"/> to this password</summary>
        public void AppendString(string s) {
            foreach (char c in s)
                AppendChar(c);
        }

        /// <summary>Creates an empty instance</summary>
        public SecurePassword() => SecureString = new();
        
        /// <summary>Create a new instance and copy the <paramref name="password"/> chars to <see cref="SecureString"/></summary>
        public SecurePassword(string password) {
            SecureString = new();
            foreach(char c in password)
                SecureString.AppendChar(c);
        }

        /// <summary>Create a new instance and assign <paramref name="password"/> to <see cref="SecureString"/></summary>
        public SecurePassword(SecureString password) {
            SecureString = password;
        }

        /// <summary>Dispose of this instance</summary>
        public void Dispose() {
            SecureString?.Dispose();
            GC.SuppressFinalize(this);
        }

    }

    /// <summary>Represents the Key and IV of an Aes encryption. Optionally holds a password and a salt to derive the key from.</summary>
    public class AesEncryption : IDisposable {

        /// <summary>The Aes key bytes</summary>
        /// <remarks>To import a key/IV/salt, use the constructor.</remarks>
        public byte[] Key { get; private set; }
        /// <summary>The initialization vector bytes</summary>
        public byte[] IV { get; private set; }
        /// <summary>The salt bytes used to derive the <c>Key</c> using <see cref="Password"/>.</summary>
        public byte[] Salt { get; private set; }

        /// <summary>Shorthand for <c>!Password.IsEmpty</c></summary>
        public bool HasPassword => !Password.IsEmpty;
        /// <summary>Shorthand for <c>Salt != null</c></summary>
        public bool HasSalt => Salt != null;

        private SecurePassword _password;
        /// <summary>The password used in combination with <c>Salt</c>. If null is provided, <see cref="string.Empty"/> is stored.</summary>
        /// <remarks>If Salt is assigned (not null), then the key is derived using the new password.</remarks>
        public SecurePassword Password {
            get => _password;
            set {
                _password = value;

                if (HasSalt && HasPassword)
                    DeriveKey();
            }
        }


        /// <summary>The default value assigned to <see cref="SaltSize"/>.</summary>
        public const int DefaultSaltSize = 32;

        /// <summary>The length of the salt used to generate the next salt.</summary>
        public int SaltSize { get; set; } = DefaultSaltSize;


        /// <summary>The default value assigned to <see cref="KeyDeriveIterations"/>.</summary>
        public const int DefaultKeyDeriveIterations = 696;

        private int _keyDeriveIterations = DefaultKeyDeriveIterations;
        /// <summary>The number of iterations used to derive the key using the password. Must be greater than 0.</summary>
        /// <remarks>If a salt and a password are assigned (not null), then the key is derived using the new iteration count.</remarks>
        public int KeyDeriveIterations {
            get => _keyDeriveIterations;
            set {

                if (_keyDeriveIterations != value) {

                    ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value, nameof(KeyDeriveIterations));

                    _keyDeriveIterations = value;

                    if (HasPassword && HasSalt)
                        DeriveKey();

                }

            }
        }

        /// <summary>Set to <c>true</c> to generate a password consisting of numbers only</summary>
        /// <remarks>Assigning a password sets this variable accordingly. Used for password generation.</remarks>
        public bool NumbersOnlyPassword { get; private set; } = false;


        private readonly object Sync = new();

        /// <summary>Generates new password, salt, IV then derives the key (in this order) based on this instance's generation properties</summary>
        public void GenerateAndFill() {

            GenerateSalt();
            GenerateIv();
            DeriveKey();

        }

        /// <summary>Creates a new instance and calls <c>GenerateAndFill()</c></summary>
        public AesEncryption(bool numbersOnlyPassword = false) {
            NumbersOnlyPassword = numbersOnlyPassword;
            GenerateAndFill();
        }

        /// <summary>Create a new instance, assign password, salt and IV, then derive the key</summary>
        public AesEncryption(string password, byte[] salt, byte[] iv, int derivingIterations = DefaultKeyDeriveIterations) {
            _password = new(password);

            IV = new byte[iv.Length];
            Array.Copy(iv, IV, IV.Length);

            Salt = new byte[salt.Length];
            Array.Copy(salt, Salt, Salt.Length);

            _keyDeriveIterations = derivingIterations;

            DeriveKey();

            NumbersOnlyPassword = Encoding.ASCII.GetBytes(password).All(k => 0x0030 <= k && k <= 0x0039); //use ascii so one byte equals one character
        }
        /// <summary>Create a new instance and assign key and IV. Does not assign password and salt.</summary>
        public AesEncryption(byte[] key, byte[] iv) {
            Key = key;
            IV = iv;
            Salt = null;
            Password = new();
        }

        #region Encrypt
        ///<summary>Encrypts a unicode string using this instance's cryptographic info.</summary>
        ///<returns>The encrypted bytes. If the encryption fails, <c>null</c>.</returns>
        public byte[] EncryptString(string data) {

            lock (Sync) {
                using var aes = Aes.Create();

                aes.Key = Key;
                aes.IV = IV;

                byte[] encrypted;
                using (var outputStream = new MemoryStream()) {
                    using var encryptorStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
                    using (var inputStream = new StreamWriter(encryptorStream, Encoding.Unicode)) {
                        try {
                            inputStream.Write(data);
                        } catch {
                            return null;
                        }
                    }
                    encrypted = outputStream.ToArray();
                }

                return encrypted;
            }
        }
        ///<summary>Encrypts bytes using this instance's cryptographic info.</summary>
        ///<returns>The encrypted bytes. If the encryption fails, <c>null</c>.</returns>
        public byte[] EncryptBytes(byte[] data) {

            lock (Sync) {

                using var aes = Aes.Create();

                aes.Key = Key;
                aes.IV = IV;

                byte[] encrypted;
                using (var outputStream = new MemoryStream()) {
                    using (var encryptorStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write)) {
                        try {
                            encryptorStream.Write(data);
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
        ///<summary>Decrypts encrypted unicode bytes using this instance's cryptographic info</summary>
        ///<returns>The decrypted bytes. If the decryption fails, <c>null</c>.</returns>
        public string DecryptString(byte[] data) {

            lock (Sync) {

                using var aes = Aes.Create();

                aes.Key = Key;
                aes.IV = IV;

                string decrypted;
                using (var inputStream = new MemoryStream(data)) {

                    using var decryptorStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
                    using var outputStream = new StreamReader(decryptorStream, Encoding.Unicode);

                    try {
                        decrypted = outputStream.ReadToEnd();
                    } catch {
                        return null;
                    }
                }

                return decrypted;
            }
        }
        ///<summary>Decrypts encrypted bytes using this instance's cryptographic info</summary>
        ///<returns>The decrypted bytes. If the decryption fails, <c>null</c>.</returns>
        public byte[] DecryptBytes(byte[] data) {

            lock (Sync) {

                using var aes = Aes.Create();

                aes.Key = Key;
                aes.IV = IV;

                byte[] decrypted;
                using (var inputStream = new MemoryStream(data)) {

                    using var decryptorStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
                    using var outputStream = new MemoryStream();

                    try {
                        decryptorStream.CopyTo(outputStream);
                    } catch {
                        return null;
                    }

                    decrypted = outputStream.ToArray();
                }

                return decrypted;
            }
        }
        #endregion
        #region Streams
        /// <summary>Create a write-mode encryptor stream using this instance's cryptographic info.</summary>
        /// <param name="target">The target stream that the CryptoStream writes to</param>\
        /// <remarks>Make sure to call <c>Dispose()</c> when no longer needed. CryptoStream then also disposes of the target stream (in .NET 8 at least).</remarks>
        public CryptoStream GetEncryptor(Stream target) {

            var aes = Aes.Create();

            aes.Key = Key;
            aes.IV = IV;

            return new CryptoStream(target, aes.CreateEncryptor(), CryptoStreamMode.Write);

        }

        /// <summary>Create a read-mode encryptor stream using the instance's cryptographic info</summary>
        /// <param name="target">The target stream that the CryptoStream writes to</param>
        /// <remarks>Make sure to call <c>Dispose()</c> when no longer needed. CryptoStream then also disposes of the target stream (in .NET 8 at least).</remarks>
        public CryptoStream GetDecryptor(Stream target) {

            using var aes = Aes.Create();
            aes.Key = Key;
            aes.IV = IV;

            return new CryptoStream(target, aes.CreateDecryptor(), CryptoStreamMode.Read);

        }
        #endregion

        /// <summary>Generate a string consisting of <paramref name="length"/> numbers</summary>
        public void GenerateNumberPassword(int length) {

            Password = new();
            for (int i = 0; i < length; i++)
                Password.AppendChar(Random.Shared.Next(0, 10).ToString()[0]);

            NumbersOnlyPassword = true;
        }

        /// <summary>Generate a random combination string of the most common characters</summary>
        public void GenerateLettersPassword(int length) {

            char[] validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?!@#$%^&*()_+-={}[];\'\"\\,./<>\\|`~".ToCharArray();
            Password = new();
            for (int i = 0; i < length; i++)
                Password.AppendChar(validChars[Random.Shared.Next(0, validChars.Length)]);

            NumbersOnlyPassword = false;
        }
        /// <summary>Assign a newly generate IV</summary>
        public void GenerateIv() {
            using var aes = Aes.Create();

            aes.GenerateIV();
            IV = aes.IV; //the Aes class copies the byte array already, so just take the reference
        }

        /// <summary>Assign a newly generated salt that is <see cref="SaltSize"/> bytes long</summary>
        public void GenerateSalt() {
            Salt = new byte[SaltSize];
            Random.Shared.NextBytes(Salt);
        }

        /// <summary>Derives <see cref="Password"/> using <see cref="Salt"/>, and iterates <see cref="KeyDeriveIterations"/> times. The bytes are assigned to this instance's key.</summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        public void DeriveKey() {

            ArgumentNullException.ThrowIfNull(Password);
            ArgumentNullException.ThrowIfNull(Salt);
            ArgumentOutOfRangeException.ThrowIfNegative(KeyDeriveIterations);

            var func = new Rfc2898DeriveBytes(Password.PasswordUnicodeBytes, Salt, KeyDeriveIterations, HashAlgorithmName.SHA512);
            Key = func.GetBytes(32);
        }

        /// <summary>Disposes of this instance</summary>
        public void Dispose() {
            IV = null;
            Key = null;
            Salt = null;
            Password.Dispose();
            Password = null;
            GC.SuppressFinalize(this);
        }
    }

    
}
