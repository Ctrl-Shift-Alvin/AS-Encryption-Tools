using AlvinSoft;
using System.Text;

namespace ASEncryptionToolsTest {
    [TestClass]
    public class AlvinSoftCryptographyTests {

        #region RSA
        [TestMethod("RSA Test Encrypt/DecryptString")]
        public void Test1() {



        }

        #endregion

        #region Aes

        public void AesTest1() {

        }

        #endregion

        static byte[] GenerateBytes() {
            byte[] bytes = new byte[Random.Shared.Next(1, 17)];
            Random.Shared.NextBytes(bytes);
            return bytes;
        }

        static string GeneratePassword() => Encoding.Unicode.GetString(GenerateBytes());

    }

}