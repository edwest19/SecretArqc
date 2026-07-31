// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Utility: Provides slicing, comparison, and safe byte-array operations used throughout EMV cryptographic processing.

namespace SecretArqc.Core.Primitives
{
    /// <summary>
    /// Utility functions for working with byte arrays.
    /// Includes slicing, equality checks, and safe copying.
    /// Used in EMV key derivation, MAC building, ARQC/ARPC, and DOL parsing.
    /// </summary>
    public static class ByteArrayUtils
    {
        /// <summary>
        /// Returns a slice of the byte array starting at the given offset for the given length.
        /// </summary>
        public static byte[] Slice(byte[] data, int offset, int length)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (offset < 0 || length < 0 || offset + length > data.Length)
                throw new ArgumentOutOfRangeException();

            var result = new byte[length];
            Buffer.BlockCopy(data, offset, result, 0, length);
            return result;
        }

        /// <summary>
        /// Compares two byte arrays for exact equality.
        /// </summary>
        public static bool AreEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null)
                return false;

            if (a.Length != b.Length)
                return false;

            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i])
                    return false;

            return true;
        }

        /// <summary>
        /// Returns a copy of the input byte array.
        /// </summary>
        public static byte[] Copy(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            var result = new byte[data.Length];
            Buffer.BlockCopy(data, 0, result, 0, data.Length);
            return result;
        }
    }
}
