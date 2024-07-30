using AlvinSoft;
using System.Text;

namespace ASEncryptionToolsTest {
    [TestClass]
    public class AlvinSoftCryptographyTests {

        #region RSA
        [TestMethod("RSAKey Export/Import Test")]
        public void Test1() {

            RsaEncryption rsa1 = new();
            RsaEncryption rsa2 = new(rsa1.Key);

            Assert.IsTrue(TestHelper.TestRsa(rsa1, rsa2, true));

            rsa1 = new();
            byte[] exportedKey = rsa1.Key.ExportPublicKey();

            rsa2 = new(RSAKey.ImportPublicKey(exportedKey));

            TestHelper.TestRsa(rsa2, rsa1, false);

            exportedKey = rsa1.Key.ExportPrivateKey();
            rsa2 = new(RSAKey.ImportPrivateKey(exportedKey));

            TestHelper.TestRsa(rsa1, rsa2, true);

        }
        

        #endregion

        #region Aes

        public void AesTest1() {

        }

        #endregion


    }

    public static class TestHelper {

        static byte[] GenerateBytes(int maxLength = 56) {
            byte[] bytes = new byte[Random.Shared.Next(1, maxLength)];
            Random.Shared.NextBytes(bytes);
            return bytes;
        }

        static string GeneratePassword(int charLength = 56) {
            char[] validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?!@#$%^&*()_+-={}[];\'\"\\,./<>\\|`~".ToCharArray();
            StringBuilder password = new();
            for (int i = 0; i < charLength; i++)
                password.Append(validChars[Random.Shared.Next(0, validChars.Length)]);

            return password.ToString();
        }

        public static bool TestRsa(RsaEncryption encryptRsa, RsaEncryption decryptRsa, bool bothWays) {
            //test1
            byte[] unencrypted = GenerateBytes();

            byte[] encrypted = encryptRsa.EncryptBytes(unencrypted);

            byte[] decrypted = decryptRsa.DecryptBytes(encrypted);

            if (!Enumerable.SequenceEqual(unencrypted, decrypted))
                return false;

            encrypted = null;
            decrypted = null;

            if (bothWays) {
                //test 2
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

            encrypted = null;
            decrypted = null;

            if (bothWays) {
                //test 4
                encrypted = decryptRsa.EncryptString(unencryptedString);

                decryptedString = encryptRsa.DecryptString(encrypted);

                if (unencryptedString != decryptedString)
                    return false;
            }

            return true;

        }
    }

}