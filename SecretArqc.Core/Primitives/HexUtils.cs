// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Utility: Provides hex-to-byte and byte-to-hex conversion used throughout EMV cryptographic processing.

using System;

namespace SecretArqc.Core.Primitives
{
    /// <summary>
    /// Utility functions for converting between hexadecimal strings and byte arrays.
    /// Used in EMV key derivation, ARQC/ARPC, DOL parsing, and general crypto operations.
    /// </summary>
    public static class HexUtils
    {
        /// <summary>
        /// Converts a hexadecimal string into a byte array.
        /// </summary>
        public static byte[] FromHex(string hex)
        {
            if (hex == null)
                throw new ArgumentNullException(nameof(hex));

            if (hex.Length % 2 != 0)
                throw new ArgumentException("Hex string must have even length.");

            var result = new byte[hex.Length / 2];

            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);

            return result;
        }

        /// <summary>
        /// Converts a byte array into an uppercase hexadecimal string.
        /// </summary>
        public static string ToHex(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            return BitConverter.ToString(data).Replace("-", "");
        }
    }
}
