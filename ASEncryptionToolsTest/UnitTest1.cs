using System.Text;
using System.Security.Cryptography;

namespace ASEncryptionToolsTest {
    [TestClass]
    public class AlvinSoftCryptographyTests {

        #region RSA
        [TestMethod("RSAKey Export/Import Test")]
        public void Test1() {

            RSAEncryption rsa1 = new();
            RSAEncryption rsa2 = new(rsa1.Key);

            Assert.IsTrue(TestHelper.TestRsa(rsa1, rsa2, true));

            rsa1 = new();
            byte[] exportedKey = rsa1.Key.ExportPublicKey();

            rsa2 = new(RSAKey.ImportPublicKey(exportedKey));

            TestHelper.TestRsa(rsa2, rsa1, false);

            exportedKey = rsa1.Key.ExportPrivateKey();
            rsa2 = new(RSAKey.ImportPrivateKey(exportedKey));

            TestHelper.TestRsa(rsa1, rsa2, true);

        }


        [TestMethod("RSAKey Export/Import PEM Test")]
        public void Test2() {

            RSAEncryption rsa1 = new();
            RSAEncryption rsa2 = new(rsa1.Key);

            Assert.IsTrue(TestHelper.TestRsa(rsa1, rsa2, true));

            rsa1 = new();
            string exportedKey = rsa1.Key.ExportPublicKeyBase64();

            rsa2 = new(RSAKey.ImportPublicKeyBase64(exportedKey));

            TestHelper.TestRsa(rsa2, rsa1, false);

            exportedKey = rsa1.Key.ExportPrivateKeyBase64();
            rsa2 = new(RSAKey.ImportPrivateKeyBase64(exportedKey));

            TestHelper.TestRsa(rsa1, rsa2, true);

        }

        [TestMethod("RSAEncryption Encrypt/Decrypt Test")]
        public void Test3() {

            RSAEncryption rsa1 = new();
            RSAEncryption rsa2 = new(rsa1.Key);

            TestHelper.TestRsa(rsa1, rsa2, true);

        }

        [TestMethod("RSAEncryption Encrypt/Decrypt async Test")]
        public async Task Test4() {

            RSAEncryption rsa1 = new();
            RSAEncryption rsa2 = new(rsa1.Key);

            Task task1 = Task.Run(() => TestHelper.TestRsa(rsa1, rsa2, false));
            Task task2 = Task.Run(() => TestHelper.TestRsa(rsa2, rsa1, false));

            await Task.WhenAll(task1, task2);

        }


        #endregion

        #region Aes

        [TestMethod("SecurePassword Test")]
        public void AesTest1() {

            string pass = TestHelper.GeneratePassword();
            SecurePassword securePass = new();

            //test empty constructor, copy string
            securePass.AppendString(pass);

            Assert.AreEqual(pass, securePass.ToString());
            securePass.Dispose();

            //test string constructor
            securePass = new(pass);
            Assert.AreEqual(pass, securePass.ToString());

            //test export
            byte[] passBytes = securePass.PasswordUnicodeBytes;
            Assert.AreEqual(pass, Encoding.Unicode.GetString(passBytes));
            securePass.Dispose();

            //test .Equals()
            pass = TestHelper.GeneratePassword();
            securePass = new(pass);

            SecurePassword securePass1 = new(pass);

            Assert.IsTrue(securePass == securePass1);
            Assert.IsTrue(securePass == securePass1.SecureString);
            Assert.IsTrue(securePass == pass);
            Assert.IsTrue(securePass == pass.ToCharArray());

            //test negative .Equals()
            pass = TestHelper.GeneratePassword();
            securePass = new(pass);

            pass = TestHelper.GeneratePassword();
            securePass1 = new(pass);

            Assert.IsFalse(securePass.Equals(securePass1));
            Assert.IsFalse(securePass.Equals(securePass1.SecureString));
            Assert.IsFalse(securePass.Equals(pass));
            Assert.IsFalse(securePass.Equals(pass.ToCharArray()));
            Assert.IsFalse(securePass.Equals(0));

        }

        [TestMethod("AesEncryption Test")]
        public void AesTest2() {

            AesEncryption encryption1 = new();
            AesEncryption encryption2 = new(encryption1.Password, encryption1.Salt, encryption1.IV);

            TestHelper.TestAes(encryption1, encryption2);

        }
        [TestMethod("AesEncryption async test")]
        public async Task AesTest3() {

            AesEncryption encryption1 = new();
            AesEncryption encryption2 = new(encryption1.Password, encryption1.Salt, encryption1.IV);

            Task task1 = Task.Run(() => TestHelper.TestAes(encryption1, encryption2, false));
            Task task2 = Task.Run(() => TestHelper.TestAes(encryption2, encryption1, false));

            await Task.WhenAll(task1, task2);

        }

        #endregion


    }

    public static class TestHelper {

        public static byte[] GenerateBytes(int maxLength = 56) {
            byte[] bytes = new byte[Random.Shared.Next(1, maxLength)];
            Random.Shared.NextBytes(bytes);
            return bytes;
        }

        public static string GeneratePassword(int charLength = 56) {
            char[] validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();
            StringBuilder password = new();
            for (int i = 0; i < charLength; i++)
                password.Append(validChars[Random.Shared.Next(0, validChars.Length)]);

            return password.ToString();
        }

        public static bool TestRsa(RSAEncryption encryptRsa, RSAEncryption decryptRsa, bool bothWays) {
            //test1
            byte[] unencrypted = GenerateBytes();

            byte[] encrypted = encryptRsa.EncryptBytes(unencrypted);

            byte[] decrypted = decryptRsa.DecryptBytes(encrypted);

            if (!Enumerable.SequenceEqual(unencrypted, decrypted))
                return false;

            //test 2?
            if (bothWays) {

                encrypted = decryptRsa.EncryptBytes(unencrypted);

                decrypted = encryptRsa.DecryptBytes(encrypted);

                if (!Enumerable.SequenceEqual(unencrypted, decrypted))
                    return false;

            }
            //test 3
            string unencryptedString = GeneratePassword();

            encrypted = encryptRsa.EncryptString(unencryptedString);

            string decryptedString = decryptRsa.DecryptString(encrypted);

            if (unencryptedString != decryptedString)
                return false;


            //test 4
            if (bothWays) {
                encrypted = decryptRsa.EncryptString(unencryptedString);

                decryptedString = encryptRsa.DecryptString(encrypted);

                if (unencryptedString != decryptedString)
                    return false;
            }

            return true;

        }

        public static bool TestAes(AesEncryption encryptAes, AesEncryption decryptAes, bool bothWays = true) {

            //test encrypt/decrypt bytes
            byte[] unencrypted = GenerateBytes();
            byte[] encrypted = encryptAes.EncryptBytes(unencrypted);
            byte[] decrypted = decryptAes.DecryptBytes(encrypted);

            CollectionAssert.AreEqual(unencrypted, decrypted);

            if (bothWays) {

                unencrypted = GenerateBytes();
                encrypted = decryptAes.EncryptBytes(unencrypted);
                decrypted = encryptAes.DecryptBytes(encrypted);

                CollectionAssert.AreEqual(unencrypted, decrypted);

            }

            //test encrypt/decrypt string
            string unencryptedString = GeneratePassword();
            byte[] encryptedString = encryptAes.EncryptString(unencryptedString);
            string decryptedString = decryptAes.DecryptString(encryptedString);

            Assert.AreEqual(unencryptedString, decryptedString);

            if (bothWays) {

                unencryptedString = GeneratePassword();
                encryptedString = decryptAes.EncryptString(unencryptedString);
                decryptedString = encryptAes.DecryptString(encryptedString);

                Assert.AreEqual(unencryptedString, decryptedString);

            }

            //test encrypt/decrypt stream
            unencrypted = GenerateBytes();

            encrypted = encryptAes.EncryptBytes(unencrypted);

            string fileName;
            do {
                fileName = Directory.GetCurrentDirectory() + '\\' + GeneratePassword(4) + ".aes";
            } while (File.Exists(fileName));


            //encrypt and send to file
            FileStream file = new(fileName, FileMode.Create, FileAccess.Write);
            CryptoStream encryptor = encryptAes.GetEncryptor(file);

            encryptor.Write(unencrypted, 0, unencrypted.Length);
            encryptor.FlushFinalBlock();

            encryptor.Dispose();


            file = new(fileName, FileMode.Open, FileAccess.Read);
            CryptoStream decryptor = decryptAes.GetDecryptor(file);

            byte[] buffer = new byte[1024];
            int bytesRead, bytesReadTotal = 0;
            while ((bytesRead = decryptor.Read(buffer, bytesReadTotal, 16)) > 0)
                bytesReadTotal += bytesRead;

            decryptor.Dispose();
            File.Delete(fileName);

            Array.Resize(ref buffer, bytesReadTotal);

            CollectionAssert.AreEqual(buffer, unencrypted);


            if (bothWays) {

                //test encrypt/decrypt stream
                unencrypted = GenerateBytes();

                encrypted = encryptAes.EncryptBytes(unencrypted);

                do {
                    fileName = Directory.GetCurrentDirectory() + '\\' + GeneratePassword(4) + ".aes";
                } while (File.Exists(fileName));


                //encrypt and send to file
                file = new(fileName, FileMode.Create, FileAccess.Write);
                encryptor = decryptAes.GetEncryptor(file);

                encryptor.Write(unencrypted, 0, unencrypted.Length);
                encryptor.FlushFinalBlock();

                encryptor.Dispose();


                file = new(fileName, FileMode.Open, FileAccess.Read);
                decryptor = encryptAes.GetDecryptor(file);

                buffer = new byte[1024];
                bytesReadTotal = 0;
                while ((bytesRead = decryptor.Read(buffer, bytesReadTotal, 16)) > 0)
                    bytesReadTotal += bytesRead;

                decryptor.Dispose();
                File.Delete(fileName);

                Array.Resize(ref buffer, bytesReadTotal);

                CollectionAssert.AreEqual(buffer, unencrypted);


            }

            return true;

        }
    }

}