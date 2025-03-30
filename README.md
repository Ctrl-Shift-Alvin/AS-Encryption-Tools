# ASEncryptionTools

*This branch is ideally functionally identical to master. It uses .NET Standard 2.1 to make it compatible with Unity. It is also probably slower.*

This is a library that abstracts the ```Aes``` and ```RSA``` classes to make encrypting and decrypting data, as well as importing/exporting encryption data, simpler.

To start, include the library in your code:
```using AlvinSoft.Cryptography;```

There are 2 main classes in the library:

```AesEncryption``` and
```RSAEncryption```

### SecurePassword

An instance of this class stores an internal ```SecureString``` instance for a safer handling of sensitive strings (like passwords).
Use the ```ToString()``` method to retrieve a string representing the password. Note: this method copies the bytes twice. Once into unmanaged memory, then back into managed memory. This method can be slow for long passwords.

## AesEncryption

A class that holds cryptographic keys for encrypting and decrypting data. The use of a ```Password``` and ```Salt``` (and all properties surrounding ```Salt```) is optional, since these two values are only used to calculate the key used for the encryption/decryption.

To start, create a new instance of the class. It will automatically generate random, cryptographically strong keys.
```var encryption = new AesEncryption();```

If you already have the cryptographic info and want to import it, use ```var encryption = new AesEncryption(string password, byte[] salt, byte[] iv, int derivingIterations = 696)``` (or the constructor with ```SecurePassword password``` instead of ```string password```), which will derive the key from the password using the provided salt and iteration count. Note that the key and IV are not validated, and trying to encrypt/decrypt using invalid data could throw a CryptographicException, if you use ```GetEncryptor()```/```GetDecryptor()```, or even worse: return wrong data.

If you have the cryptographic key and IV and do not need to use a password, use ```var encryption = new AesEncryption(byte[] key, byte[] iv)```, which will assign only the key and IV and will leave the salt and password property set to null (```HasPassword``` now returns false). Encrypting/decrypting data will work in this state.


To encrypt data using an ```AesEncryption``` instance, you can use the following methods:

```public byte[] EncryptString(string data)```: Encrypts a unicode string to a byte array

```public byte[] EncryptBytes(byte[] data)```: Encrypts a byte array to an encrypted byte array

```public string EncryptToBase64(string data)```: Shorthand for ```Convert.ToBase64String(encrypted)``` after null checks.


To decrypt data, you can use the following methods:

```public string DecryptString(byte[] data)```: Decrypts an encrypted unicode string

```public byte[] DecryptBytes(byte[] data)```: Decrypts an encrypted byte array

```public string DecryptBase64(string data)```: Shorthand for ```DecryptString(Convert.FromBase64String(data))```, but with null checks.

Note: ```public string DecryptBase64(string data)``` should only be used in combination with ```public string EncryptToBase64(string data)```, unless you are 100% certain that the string is a Base64 string.


You can also manually manipulate data using the correct CryptoStream:

```public CryptoStream GetEncryptor(Stream target)```: returns a writeonly CryptoStream, that encrypts data and writes it to ```target```.

```public CryptoStream GetDecryptor(Stream target)```: returns a readonly CryptoStream, that reads the data in ```target``` and decrypts it.

Note: make sure to call ```aesEncryption.Dispose()``` when the encryption class is no longer needed or declare a ```using``` statement


You can also access methods that the library uses internally, for convenience:

```public static string GenerateNumberPassword(int length)```: Generates a string of random number chars

```public static string GenerateLettersPassword(int length)```: Generates a string of chars randomly picked out of ```abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?!@#$%^&*()_+-={}[];'",./<>|`\~```

## RsaEncryption

A class that abstracts ```RSA``` and allows encrypting/decrypting data, based on which keys are available.

To get started, create a new instance of the class. It will automatically generate a key: ```var rsaEncryption = new RSAEncryption();```

To use existing rsa parameters, use the following. It can contain a private key, a public key or both ```var rsaEncryption = new RSAEncryption(new RSAParameters());```

To import any existing key, use the following:

```
RSAKey key = GetMeAKeyDamnIt(); //not an actual method
var rsaEncryption = new RSAEncryption(key);
```

or alternatively

```
RSAParameters key = GETMEADAMNKEY(); //also not an actual method
var rsaEncryption = new RSAEncryption(key); //shorthand for new RsaEncryption(new RSAKey(key))
```

Note: use the ```RSAKey.HasPublicKey``` and ```RSAKey.HasPrivateKey``` properties to check which keys are available.


To encrypt a unicode string, use the following: ```public byte[] EncryptString(string data)```

To encrypt bytes, use the following: ```public byte[] EncryptBytes(byte[] data)```


To decrypt an encrypted unicode string, use the following: ```public string DecryptString(byte[] encryptedData)```

To decrypt encrypted bytes, use the following: ```public byte[] DecryptBytes(byte[] data)```

For encrypting, if a private key isn't available, a CryptographicException will be thrown.

Note: make sure to call ```rsaEncryption.Dispose()``` when the encryption class is no longer needed or declare a ```using``` statement.

### RSAKey

A readonly struct that holds a ```RSAParameters``` instance and provides useful methods for exporting/importing existing keys.

To generate random public keys and private keys, use the empty constructor: ```var rsaKey = new RSAKey();```

To create an instance that represents an existing ```RSAParameters``` instance, use the following constructor:

```
RSAParameters key = ITOLDYOUTOGETMEAFREAKINGKEY(); //definitely not an actual method
var rsaKey = new RSA(key);
```

An ```RSAKey``` instance exposes a few useful properties.


```Key``` returns the underlying ```RSAParameters``` that this instance represents.

```HasPrivateKey``` returns true if a private key is available (that means that you can decrypt data).

```HasPublicKey``` returns true if a private key is available (that means that you can encrypt data).


You can export a public key and private key:

```public byte[] ExportPrivateKey()``` exports the private key in PKCS#8 format and prepends a byte 0.

Use ```public static RSAKey ImportPrivateKey(byte[] key)``` to import the exported private key. It will check if the first byte is 0, and throw an exception if it isn't. This also automatically calculates and assigns the private key.

```public byte[] ExportPublicKey()``` exports the public key in PKCS#1 format and prepends a byte 1.

Use ```public static RSAKey ImportPublicKey(byte[] key)``` to import the exported private key. It will check if the first byte is 1, and throw an exception if it isn't.


Last but not least, you can export a public/private key as a Base64 string, for a more user-friendly format:

```public string ExportPrivateKeyBase64()``` exports the instance's private key as a Base64 (PEM) encoded string. The string always starts with ```-----BEGIN RSA PRIVATE KEY-----``` and ends with ```-----END RSA PRIVATE KEY-----```.

```public string ExportPublicKeyBase64()``` exports the instance's public key as a Base64 (PEM) encoded string. The string always starts with ```-----BEGIN RSA PUBLIC KEY-----``` and ends with ```-----END RSA PUBLIC KEY-----```.

And to import a key in Base64 (PEM) encoding, use

```public static RSAKey ImportPrivateKeyBase64(string privateKey)```

and

```public static RSAKey ImportPublicKeyBase64(string publicKey)```.
