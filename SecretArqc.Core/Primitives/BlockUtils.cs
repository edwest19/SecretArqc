// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Utility: Splits byte arrays into fixed-size blocks used throughout EMV cryptographic processing.

namespace SecretArqc.Core.Primitives
{
    /// <summary>
    /// Provides block-splitting utilities for EMV cryptographic operations.
    /// Used in Retail MAC, AES CMAC, ARQC/ARPC building, and key derivation.
    /// </summary>
    public static class BlockUtils
    {
        /// <summary>
        /// Splits the input byte array into blocks of the specified size.
        /// The final block may be shorter if the data length is not a multiple of blockSize.
        /// </summary>
        public static byte[][] Split(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (blockSize <= 0)
                throw new ArgumentException("Block size must be positive.");

            int count = (data.Length + blockSize - 1) / blockSize;
            var blocks = new byte[count][];

            for (int i = 0; i < count; i++)
            {
                int offset = i * blockSize;
                int length = Math.Min(blockSize, data.Length - offset);

                blocks[i] = new byte[length];
                Buffer.BlockCopy(data, offset, blocks[i], 0, length);
            }

            return blocks;
        }
    }
}
