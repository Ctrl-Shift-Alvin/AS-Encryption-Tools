# ASEncryptionTools
is a library that abstracts the ```Aes``` and ```RSACryptoServiceProvider``` classes to make encrypting and decrypting data easy.

To start, include the library in your code:
```using AlvinSoft.Cryptography```

There are 3 main classes in the library:

```RandomGenerator```,
```AesEncryption``` and
```RsaEncryption```

## RandomGenerator

A static thread-safe class for generating random data.

To fill a byte array with random bytes, use the following:

```
byte[] buffer = new byte[32];
RandomGenerator.FillNonZeroBytes(buffer);
```

To get a byte array filled with random bytes, use the following:

```RandomGenerator.GenerateBytes(32);```

To get a random integer, use the following:

```RandomGenerator.Next(24, 53)```

To get a random positive integer, use the following:

```RandomGenerator.Next()```


## AesEncryption

A class that holds cryptographic keys for encrypting and decrypting data. It allows the use of a 'password'.

To start, create a new instance of the class. It will automatically generate random, cryptographically strong keys.
```var encryption = new AesEncryption();```

If you already have the cryptographic info and want to import it, use the following:
```var encryption = new AesEncryption(string password, byte[] salt, byte[] iv, int derivingIterations = 696)```
which will derive the key from the password using the provided salt and iteration count. Note that the Key and IV are not validated, and trying to encrypt/decrypt using invalid data will throw a CryptographicException.

If you have the cryptographic key and iv and do not need to derive the key, use the following:
```var encryption = new AesEncryption(byte[] key, byte[] iv)```
which will assign only the key and iv and will leave the salt and password property set to null. Encrypting/decrypting data will work in this state. Use the ```HasPassword``` property to check if the instance has a password assigned.


To encrypt data using an ```AesEncryption``` instance, you can use the following methods:

```public byte[] EncryptString(string data)```: Encrypts a unicode string to a byte array

```public byte[] EncryptBytes(byte[] data)```: Encrypts a byte array to an encrypted byte array

```public string EncryptToBase64(string data)```: Shorthand for ```Convert.ToBase64String(encrypted)```, but with null checks.

To decrypt data, you can use the following methods:

```public string DecryptString(byte[] data)```: Decrypts an encrypted unicode string

```public byte[] DecryptBytes(byte[] data)```: Decrypts an encrypted byte array

```public string DecryptBase64(string data)```: Shorthand for ```DecryptString(Convert.FromBase64String(data))```, but with null checks.


Note: ```public string DecryptBase64(string data)``` should only be used in combination with ```public string EncryptToBase64(string data)```, unless you are 100% certain that the string is a Base64 string.


You can also manually manipulate data using the correct CryptoStream:

```public CryptoStream GetEncryptor(Stream target)```: returns a writeonly CryptoStream with ```target``` assigned as the target stream, that encrypts data

```public CryptoStream GetDecryptor(Stream target)```: returns a readonly CryptoStream with ```target``` assigned as the target stream, that decrypts data

Note: make sure to call ```aesEncryption.Dispose()``` when the encryption class is no longer needed or declare a ```using``` statement


You can also access methods that the library uses internally, for convenience:

```public static string GenerateNumberPassword(int length)```: Generates a string of random number chars

```public static string GeneratePassword(int length)```: Generates a string of chars randomly picked out of ```abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?!@#$%^&*()_+-={}[];'",./<>|`\~```

```public static byte[] GenerateIv()```: Generates a random IV

```public static byte[] DeriveKey(string password, byte[] salt, int iterations)```: Uses ```Rfc2898DeriveBytes``` to derive a 32-byte array, with the use of the password, salt and iterates ```iterations``` times


## RsaEncryption

A class that abstracts the ```RSACryptoServiceProvider``` class and allows encrypting/decrypting data.

To get started, create a new instance of the class. It will automatically generate a 'public key' and 'private key':

```var rsaEncryption = new RsaEncryption();```

To use existing rsa parameters, use the following. It can contain a private key, a public key or both:

```var rsaEncryption = new RsaEncryption(new RSAParameters());```

To import a public key modulus and exponent, use the following:

```
var publicKey = new RsaEncryption.RsaPublicKey(modulus, exponent);
var rsaEncryption = new RsaEncryption(publicKey);
```
or alternatively

```var rsaEncryption = new RsaEncryption(modulus, exponent);```

Note: use the ```HasPublicKey``` and ```HasPrivateKey``` properties to check which keys are available.


To encrypt a unicode string, use the following:

```public byte[] EncryptString(string data)```

To encrypt bytes, use the following:

```public byte[] EncryptBytes(byte[] data)```


To decrypt an encrypted unicode string, use the following:

```public string DecryptString(byte[] encryptedData)```

To decrypt encrypted bytes, use the following:

```public byte[] DecryptBytes(byte[] data)```

For encrypting, if a private key isn't available, a CryptographicException will be thrown.

Note: make sure to call ```rsaEncryption.Dispose()``` when the encryption class is no longer needed or declare a ```using``` statement

### RsaPublicKey

Holds the modulus and exponent components of the public key, and provides a few useful methods.

There are mainly 2 constructors:

```public RsaPublicKey(byte[] modulus, byte[] exponent)``` and ```public RsaPublicKey(RSAParameters parameters)```

And there are a few useful methods available:

```public RSAParameters GetRSAParameters()```: Puts the modulus and exponent in an RSAParameters instance

```public byte[] GetBytesPackage()```: Creates a byte array that represents the public key. It consists of 4 bytes representing the modulus length, the modulus and the exponent

Use the ```public RsaPublicKey(byte[] packageBytes)``` constructor to import a byte array created by ```GetBytesPackage()```.