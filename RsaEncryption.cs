using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace AlvinSoft.Cryptography {

    /// <summary>Represents an <see cref="RSACryptoServiceProvider"/> abstraction</summary>
    public class RsaEncryption : IDisposable {
        /// <summary>The key size used to initialize the <see cref="RSACryptoServiceProvider"/></summary>
        public int RSAKeySize { get; } = 2048;
        private readonly RSACryptoServiceProvider rsa;
        /// <summary><c>true</c> if the instance contains a private key</summary>
        public bool HasPrivateKey { get; }

        /// <summary>Create a new RSA instance and generate keys</summary>
        public RsaEncryption() {
            rsa = new RSACryptoServiceProvider(RSAKeySize);
            HasPrivateKey = true;
        }

        /// <summary>Create a new RSA instance and import <paramref name="parameters"/></summary>
        public RsaEncryption(RSAParameters parameters) {
            rsa = new RSACryptoServiceProvider(RSAKeySize);
            rsa.ImportParameters(parameters);

            if (rsa.PublicOnly)
                HasPrivateKey = false;
            else
                HasPrivateKey = true;
        }

        /// <summary>Create a new RSA instance and import the provided public key values</summary>
        public RsaEncryption(byte[] publicKeyModulus, byte[] publicKeyExponent) {

            byte[] mod = new byte[publicKeyModulus.Length];
            byte[] exp = new byte[publicKeyExponent.Length];
            Array.Copy(publicKeyModulus, mod, mod.Length);
            Array.Copy(publicKeyExponent, exp, exp.Length);

            RSAParameters publicKey = new() {
                Modulus = mod,
                Exponent = exp
            };
            rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(publicKey);

            HasPrivateKey = false;
        }

        /// <summary>Create a new RSA instance and import the provided public key values</summary>
        public RsaEncryption(RsaPublicKey publicKey) : this(publicKey.Modulus, publicKey.Exponent) { }

        /// <summary>Returns all RSA parameters, including this instance's private key. Use with caution!</summary>
        public RSAParameters GetPrivateKey() => rsa.ExportParameters(true);
        /// <summary>Returns the RSA parameters containing this instance's public key only.</summary>
        public RsaPublicKey GetPublicKey() => new(rsa.ExportParameters(false));

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

        /// <summary>Disposes of this instance</summary>
        public void Dispose() {
            rsa.Dispose();
            GC.SuppressFinalize(this);
        }

        /// <summary>Represents an RSA public key, holding the modulus and exponent.</summary>
        public readonly struct RsaPublicKey {
            /// <summary>The modulus bytes</summary>
            public byte[] Modulus { get; }
            /// <summary>The exponent bytes</summary>
            public byte[] Exponent { get; }
            /// <summary>Creates a new instance and assigns a modulus and exponent</summary>
            public RsaPublicKey(byte[] modulus, byte[] exponent) {
                Modulus = modulus;
                Exponent = exponent;
            }
            /// <summary>Creates a new instance and assigns the modulus and exponent of <paramref name="param"/></summary>
            public RsaPublicKey(RSAParameters param) {
                Modulus = param.Modulus;
                Exponent = param.Exponent;
            }
            /// <summary>Creates a new instance and imports bytes exported by <see cref="GetBytesPackage"/></summary>
            /// <exception cref="ArgumentException"/>
            public RsaPublicKey(byte[] packageBytes) {

                int modulusSize = BitConverter.ToInt32(packageBytes, 0);
                int exponentSize = packageBytes.Length - 4 - modulusSize;

                if (4 + modulusSize + exponentSize != packageBytes.Length)
                    throw new ArgumentException("Invalid package");

                Modulus = new byte[modulusSize];
                Exponent = new byte[exponentSize];

                var array = packageBytes.Skip(4).Take(modulusSize).ToArray();
                array.CopyTo(Modulus, 0);
                packageBytes.Skip(4 + modulusSize).ToArray().CopyTo(Exponent, 0);
            }
            /// <summary>Convert this instance to <see cref="RSAParameters"/></summary>
            public RSAParameters GetRSAParameters() => new() { Modulus = Modulus, Exponent = Exponent };

            /// <summary>A byte array where the first 4 bytes represent the length of the modulus and the modulus and exponent preceede</summary>
            /// <remarks>Serialize again with the <see cref="RsaPublicKey(byte[])"/> constructor</remarks>
            public byte[] GetBytesPackage() {

                using var bytes = new MemoryStream(sizeof(int) + Modulus.Length + Exponent.Length);

                bytes.Write(BitConverter.GetBytes(Modulus.Length), 0, sizeof(int)); //write header (length of modulus)
                bytes.Write(Modulus, 0, Modulus.Length);
                bytes.Write(Exponent, 0, Exponent.Length);

                return bytes.ToArray();
            }

        }
    }
}
