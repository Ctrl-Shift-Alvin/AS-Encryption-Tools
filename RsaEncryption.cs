using System;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Linq;

namespace AlvinSoft.Cryptography {

    /// <summary>Abstracts <see cref="RSA"/> and provides simple methods for importing/exporting public/private keys, and encrypting/decrypting.</summary>
    public class RSAEncryption {

        /// <summary>Abstracts <see cref="RSA"/> and provides simple methods for importing/exporting public/private keys, and encrypting/decrypting.</summary>
        public RSAEncryption(RSAKey key) {
            Key = key;
        }

        /// <summary>Create a new RSA instance and generate a key</summary>
        public RSAEncryption() : this(new RSAKey()) { }

        /// <summary>The key size in bits used to initialize the <see cref="RSACryptoServiceProvider"/></summary>
        public int RSAKeySize { get; } = 2048;

        /// <summary>The RSA encryption parameters</summary>
        public RSAKey Key { get; private set; }

        /// <summary>Create a new RSA instance and import <paramref name="parameters"/></summary>
        public RSAEncryption(RSAParameters parameters) : this(new RSAKey(parameters)) { }


        /// <summary>Encrypt <paramref name="data"/> using this instance's public key</summary>
        /// <returns>The encrypted bytes. If anything fails, <c>null</c>.</returns>
        public byte[] EncryptBytes(byte[] data) {

            if (!Key.HasPublicKey)
                throw new CryptographicException("You need a public key to encrypt data.");

            try {
                using RSA rsa = Key.CreateRSA();
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA512);
            } catch {
                return null;
            }
        }

        /// <summary>Decrypt <paramref name="data"/> using this instance's private key</summary>
        /// <returns>The encrypted bytes. If anything fails, <c>null</c>.</returns>
        /// <exception cref="CryptographicException"/>
        public byte[] DecryptBytes(byte[] data) {

            if (!Key.HasPrivateKey)
                throw new CryptographicException("You need a private key to decrypt data.");

            try {
                using RSA rsa = Key.CreateRSA();
                return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA512);
            } catch {
                return null;
            }
        }

        /// <summary>Encrypt unicode string <paramref name="data"/> using this instance's public key</summary>
        /// <returns>The encrypted bytes. If anything fails, <c>null</c>.</returns>
        public byte[] EncryptString(string data) {

            if (!Key.HasPublicKey)
                throw new CryptographicException("You need a public key to encrypt data.");

            try {
                using RSA rsa = Key.CreateRSA();
                return rsa.Encrypt(Encoding.Unicode.GetBytes(data), RSAEncryptionPadding.OaepSHA512);
            } catch {
                return null;
            }
        }

        /// <summary>Decrypt encrypted unicode string bytes <paramref name="encryptedData"/> using this instance's private key</summary>
        /// <returns>The encrypted bytes. If anything fails, <c>null</c>.</returns>
        /// <exception cref="CryptographicException"/>
        public string DecryptString(byte[] encryptedData) {

            if (!Key.HasPrivateKey)
                throw new CryptographicException("You need a private key to decrypt data.");

            try {
                using RSA rsa = Key.CreateRSA();
                return Encoding.Unicode.GetString(rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA512));
            } catch {
                return null;
            }
        }


    }

    /// <summary>Represents an RSA key, with or without the private key.</summary>
    public class RSAKey {

        /// <summary>The used RSA key</summary>
        public RSAParameters Key { get; }

        /// <summary>true if <see cref="Key"/> contains a private key; otherwise false.</summary>
        public bool HasPrivateKey { get; }
        /// <summary>true if <see cref="Key"/> contains a public key; otherwise false.</summary>
        public bool HasPublicKey { get; }

        /// <summary>
        /// Create a new <see cref="RSA"/> instance and import this instance's key.
        /// </summary>
        /// <returns>The RSA instance</returns>
        public RSA CreateRSA() => RSA.Create(Key);

        /// <summary>
        /// Create an instance with a generated key
        /// </summary>
        public RSAKey() {

            using RSA rsa = RSA.Create();
            Key = rsa.ExportParameters(true);

            HasPrivateKey = true;
            HasPublicKey = true;

        }
        /// <summary>
        /// Create an instance that holds an RSA key with import/export functionality
        /// </summary>
        /// <param name="parameters">The parameters used export the key from</param>
        /// <exception cref="ArgumentException"/>
        public RSAKey(RSAParameters parameters) {

            Key = parameters;

            using RSA rsa = RSA.Create();
            rsa.ImportParameters(parameters);

            if (Key.Modulus?.Length > 0 && Key.Exponent?.Length > 0)
                HasPublicKey = true;
            else
                HasPublicKey = false;

            if (Key.D?.Length > 0 &&
                Key.P?.Length > 0 &&
                Key.Q?.Length > 0 &&
                Key.DP?.Length > 0 &&
                Key.DQ?.Length > 0 &&
                Key.InverseQ?.Length > 0)
                HasPrivateKey = true;
            else
                HasPrivateKey = false;

        }

        #region Import_Export

        /// <summary>
        /// Export the private key
        /// </summary>
        /// <exception cref="ArgumentException"/>
        public byte[] ExportPrivateKey() {

            if (!HasPrivateKey)
                throw new ArgumentException("The provided key doesn't have all private components but you tried to export them.");

            using RSA rsa = RSA.Create();
            rsa.ImportParameters(Key);

            byte[] bytes = rsa.ExportPkcs8PrivateKey();

            return Enumerable.Prepend<byte>(bytes, 0).ToArray(); //no idea why, but the extension IEnumerable<T>.Prepend(this IEnumerable<T> source, byte value) does not compile... some weird bug I guess...

        }

        /// <summary>
        /// Import an exported private key and calculate the public key.
        /// </summary>
        /// <param name="key">A key exported with <see cref="ExportPrivateKey"/></param>
        /// <exception cref="ArgumentException"/>
        public static RSAKey ImportPrivateKey(byte[] key) {

            if (key[0] != 0)
                throw new ArgumentException("The provided key is not a private key!", nameof(key));

            using RSA rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(key.AsSpan(1), out _);

            return new RSAKey(rsa.ExportParameters(true));

        }

        /// <summary>
        /// Export the public key
        /// </summary>
        /// <exception cref="ArgumentException"/>
        public byte[] ExportPublicKey() {

            if (!HasPublicKey)
                throw new ArgumentException("The provided key doesn't have all public components but you tried to export them.");

            using RSA rsa = RSA.Create();
            rsa.ImportParameters(Key);

            byte[] bytes = rsa.ExportRSAPublicKey();

            return Enumerable.Prepend<byte>(bytes, 1).ToArray(); //ugh... see line 161

        }
        /// <summary>
        /// Import an exported public key
        /// </summary>
        /// <param name="key">A key exported with <see cref="ExportPublicKey"/></param>
        /// <exception cref="ArgumentException"/>
        public static RSAKey ImportPublicKey(byte[] key) {

            if (key[0] != 1)
                throw new ArgumentException("The provided key is not a public key!", nameof(key));

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(key.AsSpan(1), out _);

            return new RSAKey(rsa.ExportParameters(false));

        }
        #endregion

        #region Base64

        /// <summary>
        /// Export the private key as a Base64 string (PEM)
        /// </summary>
        /// <remarks>The string always starts with <c>-----BEGIN RSA PRIVATE KEY-----</c> and ends with <c>-----END RSA PRIVATE KEY-----</c></remarks>
        /// <returns>The encoded Base64 string</returns>
        public string ExportPrivateKeyBase64() {

            if (!HasPrivateKey)
                throw new ArgumentException("The provided key doesn't have all private components but you tried to export them.");

            using RSA rsa = RSA.Create();
            rsa.ImportParameters(Key);

            var privateKeyBytes = rsa.ExportRSAPrivateKey();
            var privateKeyBase64 = Convert.ToBase64String(privateKeyBytes);
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
            for (int i = 0; i < privateKeyBase64.Length; i += 64) {
                sb.AppendLine(privateKeyBase64.Substring(i, Math.Min(64, privateKeyBase64.Length - i)));
            }
            sb.AppendLine("-----END RSA PRIVATE KEY-----");
            return sb.ToString();
        }

        /// <summary>
        /// Import a Base64 encoded (PEM) private key
        /// </summary>
        public static RSAKey ImportPrivateKeyBase64(string privateKey) {

            var keyLines = privateKey.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                     .Where(line => !line.StartsWith("-----")).ToArray();
            var keyBase64 = string.Join("", keyLines);
            var keyBytes = Convert.FromBase64String(keyBase64);

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(keyBytes, out _);

            return new RSAKey(rsa.ExportParameters(true));
        }

        /// <summary>
        /// Export the public key as a Base64 string (PEM)
        /// </summary>
        /// <remarks>The string always starts with <c>-----BEGIN RSA PUBLIC KEY-----</c> and ends with <c>-----END RSA PUBLIC KEY-----</c></remarks>
        /// <returns>The encoded Base64 string</returns>
        public string ExportPublicKeyBase64() {

            if (!HasPublicKey)
                throw new ArgumentException("The provided key doesn't have all public components but you tried to export them.");

            using RSA rsa = RSA.Create();
            rsa.ImportParameters(Key);

            var publicKeyBytes = rsa.ExportRSAPublicKey();
            var publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN RSA PUBLIC KEY-----");
            for (int i = 0; i < publicKeyBase64.Length; i += 64) {
                sb.AppendLine(publicKeyBase64.Substring(i, Math.Min(64, publicKeyBase64.Length - i)));
            }
            sb.AppendLine("-----END RSA PUBLIC KEY-----");
            return sb.ToString();
        }

        /// <summary>  
        /// Import a Base64 encoded (PEM) public key  
        /// </summary>  
        public static RSAKey ImportPublicKeyBase64(string publicKey) {

            var keyLines = publicKey.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                    .Where(line => !line.StartsWith("-----")).ToArray();

            var keyBase64 = string.Join("", keyLines);
            var keyBytes = Convert.FromBase64String(keyBase64);
            using RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(keyBytes, out _);

            return new RSAKey(rsa.ExportParameters(false));
        }

        #endregion

    }
}
