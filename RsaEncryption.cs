using System;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Buffers.Binary;

namespace AlvinSoft.Cryptography {

    /// <summary>Abstracts <see cref="RSA"/> and provides simple methods for importing/exporting public/private keys, and encrypting/decrypting.</summary>
    [UnsupportedOSPlatform("browser")]
    public class RsaEncryption(RSAKey key) {
        /// <summary>The key size in bits used to initialize the <see cref="RSACryptoServiceProvider"/></summary>
        public int RSAKeySize { get; } = 2048;

        /// <summary>The RSA encryption parameters</summary>
        public RSAKey Key = key;

        /// <summary>Create a new RSA instance and generate a key</summary>
        public RsaEncryption() : this(new RSAKey()) { }

        /// <summary>Create a new RSA instance and import <paramref name="parameters"/></summary>
        public RsaEncryption(RSAParameters parameters) : this(new RSAKey(parameters)) { }


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
    [UnsupportedOSPlatform("browser")]
    public readonly struct RSAKey {

        /// <summary>The used RSA key</summary>
        public RSAParameters Key { get; }

        /// <summary>true if <see cref="Key"/> contains a private key; otherwise false.</summary>
        public bool HasPrivateKey { get; } = false;
        /// <summary>true if <see cref="Key"/> contains a public key; otherwise false.</summary>
        public bool HasPublicKey { get; } = false;

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

            if (Key.D?.Length > 0 &&
                Key.P?.Length > 0 &&
                Key.Q?.Length > 0 &&
                Key.DP?.Length > 0 &&
                Key.DQ?.Length > 0 &&
                Key.InverseQ?.Length > 0)
                HasPrivateKey = true;

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

            return AddPrefix(0, bytes);

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

            return new(rsa.ExportParameters(true));

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

            return AddPrefix(1, bytes);

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

            return new(rsa.ExportParameters(false));

        }

        /// <summary>
        /// Export the full key
        /// </summary>
        /// <exception cref="ArgumentException"/>
        public byte[] ExportFullKey() {

            using RSA rsa = RSA.Create();
            rsa.ImportParameters(Key);

            byte[] privateKey = ExportPrivateKey();
            byte[] publicKey = ExportPublicKey();

            byte[] result = new byte[1 + 4 + privateKey.Length + publicKey.Length];

            result[0] = 2;

            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan()[1..], privateKey.Length); //write private key length

            Array.Copy(privateKey, 0, result, 5, privateKey.Length); //copy private key
            Array.Copy(publicKey, 0, result, 5 + privateKey.Length, publicKey.Length); //copy public key

            return result;

        }
        /// <summary>
        /// Import an exported key
        /// </summary>
        /// <param name="key">A key exported with <see cref="ExportFullKey"/></param>
        /// <exception cref="ArgumentException"/>
        public static RSAKey ImportFullKey(byte[] key) {

            if (key[0] != 2)
                throw new ArgumentException("The provided key is not a full key!", nameof(key));

            int privateKeyLength = BinaryPrimitives.ReadInt32BigEndian(key.AsSpan()[1..]);
            int publicKeyLength = key.Length - privateKeyLength - 5;

            ReadOnlySpan<byte> privateKey;
            ReadOnlySpan<byte> publicKey;

            privateKey = key.AsSpan(5, privateKeyLength);
            publicKey = key.AsSpan(privateKeyLength + 5, publicKeyLength);


            RSAParameters parameters = new();
            using RSA rsa = RSA.Create();

            //import private key and export to "parameters"
            rsa.ImportPkcs8PrivateKey(privateKey, out _);
            parameters = rsa.ExportParameters(true);

            //import public key and assign the rest of the fields
            rsa.ImportRSAPublicKey(key, out _);
            RSAParameters publicParams = rsa.ExportParameters(false);
            parameters.Modulus = publicParams.Modulus;
            parameters.Exponent = publicParams.Exponent;

            return new(rsa.ExportParameters(true));

        }
        #endregion

        #region Base64

        /// <summary>
        /// Export the private key as a Base64 string
        /// </summary>
        /// <remarks>The string always starts with <c>-----BEGIN RSA PRIVATE KEY-----</c> and ends with <c>-----END RSA PRIVATE KEY-----</c></remarks>
        /// <returns>The encoded Base64 string</returns>
        public string ExportPrivateKeyBase64() {

            if (!HasPrivateKey)
                throw new ArgumentException("The provided key doesn't have all private components but you tried to export them.");

            using RSA rsa = RSA.Create();
            rsa.ImportParameters(Key);

            return rsa.ExportRSAPrivateKeyPem();
        }

        /// <summary>
        /// Export the public key as a Base64 string
        /// </summary>
        /// <remarks>The string always starts with <c>-----BEGIN RSA PRIVATE KEY-----</c> and ends with <c>-----END RSA PRIVATE KEY-----</c></remarks>
        /// <returns>The encoded Base64 string</returns>
        public string ExportPublicKeyBase64() {

            if (!HasPublicKey)
                throw new ArgumentException("The provided key doesn't have all public components but you tried to export them.");

            using RSA rsa = RSA.Create();
            rsa.ImportParameters(Key);

            return rsa.ExportRSAPublicKeyPem();
        }

        #endregion

        private static byte[] AddPrefix(byte prefix, byte[] data) {
            byte[] result = new byte[data.Length + 1];
            result[0] = prefix;
            Array.Copy(data, 0, result, 1, data.Length);
            return result;
        }

    }
}
