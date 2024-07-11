using AlvinSoft;

namespace ASEncryptionToolsTest {
    [TestClass]
    public class AlvinSoftCryptographyTests {

        #region RSA
        [TestMethod("AlvinSoft.Encryption.RSA Test Encrypt/DecryptString")]
        public void RSATest() {

            var rsaOriginal = new RsaEncryption(); //server

            var rsaPublic = new RsaEncryption(rsaOriginal.GetPublicKey()); //client

            string unencrypted = AesEncryption.GeneratePassword(15);

            byte[] encrypted = rsaPublic.EncryptString(unencrypted);

            string decrypted = rsaOriginal.DecryptString(encrypted);

            Assert.AreEqual(unencrypted, decrypted);

        }

        [TestMethod("AlvinSoft.Encryption.RSA Test Encrypt/DecryptBytes")]
        public void RSATest1() {

            var rsaOriginal = new RsaEncryption(); //server

            var rsaPublic = new RsaEncryption(rsaOriginal.GetPublicKey()); //client

            byte[] unencrypted = RandomGenerator.GenerateBytes(16);

            byte[] encrypted = rsaPublic.EncryptBytes(unencrypted);

            byte[] decrypted = rsaOriginal.DecryptBytes(encrypted);

            CollectionAssert.AreEqual(unencrypted, decrypted);

        }

        [TestMethod("AlvinSoft.Encryption.RSA Test RsaPublicKey")]
        public void RSATest2() {

            RsaEncryption rsa;
            RsaEncryption rsa1 = new();

            byte[] publicPackage = rsa1.GetPublicKey().GetBytesPackage();

            rsa = new(new RsaEncryption.RsaPublicKey(publicPackage));

            string initial = AesEncryption.GeneratePassword(31);
            byte[] encrypted = rsa.EncryptString(initial);
            string decrypted = rsa1.DecryptString(encrypted);

            Assert.AreEqual(initial, decrypted);

        }
        #endregion

        #region Aes
        [TestMethod("AlvinSoft.Encryption Test Encrypt/DecryptString")]
        public void AES256Test() {

            var encrOriginal = new AesEncryption();

            var encrPublic = new AesEncryption(encrOriginal.Password, encrOriginal.Salt, encrOriginal.IV);

            string unencrypted = AesEncryption.GeneratePassword(1024);

            byte[] encrypted = encrOriginal.EncryptString(unencrypted);

            string decrypted = encrPublic.DecryptString(encrypted);

            Assert.AreEqual(unencrypted, decrypted);
        }

        [TestMethod("AlvinSoft.Encryption Test Encrypt/DecryptToBytes")]
        public void AES256Test1() {

            var encrOriginal = new AesEncryption();

            var encrPublic = new AesEncryption(encrOriginal.Password, encrOriginal.Salt, encrOriginal.IV);

            byte[] unencrypted = RandomGenerator.GenerateBytes(1024);

            byte[] encrypted = encrOriginal.EncryptBytes(unencrypted);

            byte[] decrypted = encrPublic.DecryptBytes(encrypted);

            CollectionAssert.AreEqual(unencrypted, decrypted);

            encrOriginal.Dispose();
        }

        [TestMethod("AlvinSoft.Encryption Test NumbersOnlyPassword")]
        public void AES256Test2() {

            var encr = new AesEncryption("123123123", RandomGenerator.GenerateBytes(32), AesEncryption.GenerateIv());

            Assert.IsTrue(encr.NumbersOnlyPassword);

            encr = new AesEncryption("l1231238192381293", encr.Salt, encr.IV);
            Assert.IsTrue(!encr.NumbersOnlyPassword);

        }

        [TestMethod("AlvinSoft.Encryption Test GetEncryptor/Decryptor")]
        public void AES256Test3() {

            var encryption = new AesEncryption();

            byte[] initial = RandomGenerator.GenerateBytes(32);

            var memory = new MemoryStream();
            var result = new MemoryStream();

            var eStream = encryption.GetEncryptor(memory);
            eStream.Write(initial, 0, initial.Length);
            eStream.FlushFinalBlock();

            memory.Position = 0;
            var dStream = encryption.GetDecryptor(memory);
            dStream.CopyTo(result);

            eStream.Dispose();
            dStream.Dispose();
            encryption.Dispose();

            CollectionAssert.AreEqual(initial, result.ToArray());

        }

        [TestMethod("AlvinSoft.Encryption Test DeriveKey")]
        public void AES256Test4() {

            string password = AesEncryption.GeneratePassword(34);
            byte[] salt = RandomGenerator.GenerateBytes(32);


            byte[] key1 = AesEncryption.DeriveKey(password, salt, 9999);
            byte[] key2 = AesEncryption.DeriveKey(password, salt, 9999);

            CollectionAssert.AreEqual(key1, key2);

        }
        #endregion

    }
}