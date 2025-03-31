using System;
using System.Text;
using System.Security;
using System.Runtime.InteropServices;

namespace AlvinSoft.Cryptography;

/// <summary>Represents a password securely stored in memory.</summary>
public class SecurePassword : IDisposable {

    /// <summary>The <see cref="System.Security.SecureString"/> instance that is storing the password.</summary>
    public SecureString SecureString { get; private set; }

    /// <summary>The character password's length.</summary>
    public int Length => SecureString.Length;

    /// <summary>Shorthand for <c>Length == 0</c>.</summary>
    public bool IsEmpty => Length == 0;


    /// <summary>Returns the unicode bytes of the password. Shorthand for <c>Encoding.Unicode.GetBytes(PasswordChars)</c>.</summary>
    public byte[] PasswordUnicodeBytes => Encoding.Unicode.GetBytes(ToString());

    /// <summary>Append <paramref name="c"/> to this password.</summary>
    public void AppendChar(char c) => SecureString.AppendChar(c);

    /// <summary>Append <paramref name="s"/> to this password.</summary>
    public void AppendString(string s)
    {
        foreach (char c in s)
            AppendChar(c);
    }

    /// <summary>Creates an empty instance.</summary>
    public SecurePassword() => SecureString = new();

    /// <summary>Create a new instance and copy the <paramref name="password"/> chars to <see cref="SecureString"/>.</summary>
    public SecurePassword(string password)
    {
        SecureString = new();
        foreach (char c in password)
            SecureString.AppendChar(c);
    }

    /// <summary>Create a new instance and assign <paramref name="password"/> to <see cref="SecureString"/>.</summary>
    public SecurePassword(SecureString password)
    {
        SecureString = password;
    }

    /// <summary>Copy the <see cref="SecureString"/> character bytes to a string.</summary>
    /// <returns>The string containing the <see cref="SecureString"/> chars.</returns>
    public override string ToString()
    {
        nint ptr = IntPtr.Zero;
        try
        {
            ptr = SecureStringMarshal.SecureStringToGlobalAllocUnicode(SecureString);
            return Marshal.PtrToStringUni(ptr);
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(ptr);
        }
    }

    /// <summary>
    /// Check if the underlying unicode chars of this instance and <paramref name="obj"/> are identical.
    /// </summary>
    /// <remarks><paramref name="obj"/> can be a <see cref="SecurePassword"/>, <see cref="SecureString"/>, <see cref="string"/> or <see cref="char"/>[] instance.</remarks>
    /// <param name="obj"></param>
    /// <returns>true if <paramref name="obj"/> is a text type and the char bytes are identical.</returns>
    public override bool Equals(object obj)
    {

        if (obj is SecurePassword securePassword)
        {

            nint thisPtr = IntPtr.Zero;
            nint objPtr = IntPtr.Zero;
            try
            {

                thisPtr = SecureStringMarshal.SecureStringToCoTaskMemUnicode(SecureString);
                objPtr = SecureStringMarshal.SecureStringToCoTaskMemUnicode(securePassword.SecureString);

                if (thisPtr == IntPtr.Zero)
                    return objPtr == IntPtr.Zero;

                int thisLength = Length;
                int objLength = securePassword.Length;
                if (thisLength != objLength)
                    return false;

                unsafe
                {

                    char* thisStart = (char*)thisPtr.ToPointer();
                    char* objStart = (char*)objPtr.ToPointer();

                    for (int i = 0; i < thisLength; i++)
                    {
                        if (thisStart[i] != objStart[i])
                            return false;
                    }
                }

                return true;


            }
            finally
            {

                Marshal.ZeroFreeCoTaskMemUnicode(thisPtr);
                Marshal.ZeroFreeCoTaskMemUnicode(objPtr);
            }

        }

        if (obj is SecureString secureString)
        {

            nint thisPtr = IntPtr.Zero;
            nint objPtr = IntPtr.Zero;
            try
            {

                thisPtr = SecureStringMarshal.SecureStringToCoTaskMemUnicode(SecureString);
                objPtr = SecureStringMarshal.SecureStringToCoTaskMemUnicode(secureString);

                if (thisPtr == IntPtr.Zero)
                    return objPtr == IntPtr.Zero;

                int thisLength = Length;
                int objLength = secureString.Length;
                if (thisLength != objLength)
                    return false;

                unsafe
                {

                    char* thisStart = (char*)thisPtr.ToPointer();
                    char* objStart = (char*)objPtr.ToPointer();

                    for (int i = 0; i < thisLength; i++)
                    {
                        if (thisStart[i] != objStart[i])
                            return false;
                    }
                }

                return true;


            }
            finally
            {

                Marshal.ZeroFreeCoTaskMemUnicode(thisPtr);
                Marshal.ZeroFreeCoTaskMemUnicode(objPtr);
            }

        }

        if (obj is string passwordString)
        {

            nint thisPtr = IntPtr.Zero;
            nint objPtr = IntPtr.Zero;
            try
            {

                thisPtr = SecureStringMarshal.SecureStringToCoTaskMemUnicode(SecureString);
                objPtr = Marshal.StringToCoTaskMemUni(passwordString);

                if (thisPtr == IntPtr.Zero)
                    return objPtr == IntPtr.Zero;

                int thisLength = Length;
                int objLength = passwordString.Length;
                if (thisLength != objLength)
                    return false;

                unsafe
                {

                    char* thisStart = (char*)thisPtr.ToPointer();
                    char* objStart = (char*)objPtr.ToPointer();

                    for (int i = 0; i < thisLength; i++)
                    {
                        if (thisStart[i] != objStart[i])
                            return false;
                    }
                }

                return true;


            }
            finally
            {

                Marshal.ZeroFreeCoTaskMemUnicode(thisPtr);
                Marshal.FreeCoTaskMem(objPtr);
            }
        }

        if (obj is char[] passwordChars)
        {
            nint thisPtr = IntPtr.Zero;
            try
            {

                thisPtr = SecureStringMarshal.SecureStringToCoTaskMemUnicode(SecureString);

                if (thisPtr == IntPtr.Zero)
                    return passwordChars == null;

                int thisLength = Length;
                int objLength = passwordChars.Length;
                if (thisLength != objLength)
                    return false;

                unsafe
                {

                    char* thisStart = (char*)thisPtr.ToPointer();

                    for (int i = 0; i < thisLength; i++)
                    {
                        if (thisStart[i] != passwordChars[i])
                            return false;
                    }
                }

                return true;


            }
            finally
            {

                Marshal.ZeroFreeCoTaskMemUnicode(thisPtr);
            }
        }

        return false;
    }

    #region Operators
    /// <returns>true if both sides contain the same unicode bytes; otherwise false.</returns>
    public static bool operator ==(SecurePassword left, SecurePassword right) => left.Equals(right);
    /// <returns>false if both sides contain the same unicode bytes; otherwise true.</returns>
    public static bool operator !=(SecurePassword left, SecurePassword right) => !left.Equals(right);

    /// <returns>true if both sides contain the same unicode bytes; otherwise false.</returns>
    public static bool operator ==(SecurePassword left, string right) => left.Equals(right);
    /// <returns>false if both sides contain the same unicode bytes; otherwise true.</returns>
    public static bool operator !=(SecurePassword left, string right) => !left.Equals(right);

    /// <returns>true if both sides contain the same unicode bytes; otherwise false.</returns>
    public static bool operator ==(string left, SecurePassword right) => right.Equals(left);
    /// <returns>false if both sides contain the same unicode bytes; otherwise true.</returns>
    public static bool operator !=(string left, SecurePassword right) => !right.Equals(left);

    /// <returns>true if both sides contain the same unicode bytes; otherwise false.</returns>
    public static bool operator ==(SecureString left, SecurePassword right) => right.Equals(left);
    /// <returns>false if both sides contain the same unicode bytes; otherwise true.</returns>
    public static bool operator !=(SecureString left, SecurePassword right) => !right.Equals(left);

    /// <returns>true if both sides contain the same unicode bytes; otherwise false.</returns>
    public static bool operator ==(SecurePassword left, SecureString right) => left.Equals(right);
    /// <returns>false if both sides contain the same unicode bytes; otherwise true.</returns>
    public static bool operator !=(SecurePassword left, SecureString right) => !left.Equals(right);

    /// <returns>true if both sides contain the same unicode bytes; otherwise false.</returns>
    public static bool operator ==(char[] left, SecurePassword right) => right.Equals(left);
    /// <returns>false if both sides contain the same unicode bytes; otherwise true.</returns>
    public static bool operator !=(char[] left, SecurePassword right) => !right.Equals(left);

    /// <returns>true if both sides contain the same unicode bytes; otherwise false.</returns>
    public static bool operator ==(SecurePassword left, char[] right) => left.Equals(right);
    /// <returns>false if both sides contain the same unicode bytes; otherwise true.</returns>
    public static bool operator !=(SecurePassword left, char[] right) => !left.Equals(right);

    #endregion
    /// <summary>Disposes of this instance.</summary>
    public void Dispose()
    {
        SecureString?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>Serves as the default hash function.</summary>
    /// <returns>A hash code for the current object.</returns>
    public override int GetHashCode() => HashCode.Combine(SecureString);
}