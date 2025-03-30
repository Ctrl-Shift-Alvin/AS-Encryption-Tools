using System;

/// <summary>
/// Shared, thread-safe <see cref="Random"/> instance.
/// </summary>
internal static class Rdm {
    public static Random Shared = new Random();
    public static byte[] GetBytes(int length) {
        byte[] buffer = new byte[length];
        lock (Shared)
            Shared.NextBytes(buffer);
        return buffer;
    }
    public static int Next(int min, int max) {
        lock (Shared)
            return Shared.Next(min, max);
    }
}
