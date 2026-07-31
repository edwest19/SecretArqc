// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Utility: Implements ISO/IEC 9797-1 Padding Method 2 used in EMV Retail MAC and ARQC/ARPC MAC building.

namespace SecretArqc.Core.Primitives
{
    /// <summary>
    /// Provides ISO/IEC 9797-1 Padding Method 2 (0x80 then 0x00).
    /// Required for EMV MAC operations including ARQC and ARPC.
    /// </summary>
    public static class PaddingUtils
    {
        public static byte[] Iso9797M2(byte[] data, int blockSize = 8)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (blockSize <= 0)
                throw new ArgumentException("Block size must be positive.");

            int padLength = blockSize - (data.Length % blockSize);
            if (padLength == 0)
                padLength = blockSize;

            var result = new byte[data.Length + padLength];

            Buffer.BlockCopy(data, 0, result, 0, data.Length);

            result[data.Length] = 0x80; // first padding byte

            // remaining bytes default to 0x00

            return result;
        }
    }
}
