// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Utility: Performs byte-wise XOR operations used throughout EMV cryptographic processing.

namespace SecretArqc.Core.Primitives
{
    /// <summary>
    /// Provides XOR operations for equal-length byte arrays.
    /// Used in EMV MAC building, ARQC/ARPC, CMAC, and key derivation.
    /// </summary>
    public static class XorUtils
    {
        public static byte[] Xor(byte[] a, byte[] b)
        {
            if (a == null || b == null)
                throw new ArgumentNullException();

            if (a.Length != b.Length)
                throw new ArgumentException("Arrays must be the same length.");

            var result = new byte[a.Length];

            for (int i = 0; i < a.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);

            return result;
        }
    }
}
