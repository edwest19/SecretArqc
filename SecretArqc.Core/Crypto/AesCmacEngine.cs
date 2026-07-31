// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Crypto Engine: Implements AES-CMAC (RFC 4493) used in EMV AES Option 3 key derivation and MAC generation.

using System;
using SecretArqc.Core.Primitives;

namespace SecretArqc.Core.Crypto
{
    /// <summary>
    /// Provides AES-CMAC generation according to RFC 4493.
    /// Used in EMV AES Option 3 key derivation, ARQC/ARPC (AES variants),
    /// and secure messaging flows.
    /// </summary>
    public class AesCmacEngine
    {
        private readonly AesEngine _aes = new AesEngine();

        /// <summary>
        /// Generates AES-CMAC for the given message using the provided AES key.
        /// </summary>
        public byte[] ComputeCmac(byte[] key, byte[] message)
        {
            if (key == null || message == null)
                throw new ArgumentNullException();

            // Step 1: Generate subkeys K1 and K2
            var (K1, K2) = GenerateSubkeys(key);

            // Step 2: Split message into 16-byte blocks
            var blocks = BlockUtils.Split(message, 16);

            bool lastBlockComplete = (message.Length % 16 == 0);

            byte[] lastBlock;

            if (lastBlockComplete)
            {
                // M_last XOR K1
                lastBlock = XorUtils.Xor(blocks[^1], K1);
            }
            else
            {
                // Pad last block, then XOR K2
                var padded = PaddingUtils.Iso9797M2(blocks[^1], 16);
                lastBlock = XorUtils.Xor(padded, K2);
            }

            // Step 3: CBC-MAC over all blocks except last
            byte[] X = new byte[16]; // initial vector = 0x00...00

            for (int i = 0; i < blocks.Length - 1; i++)
            {
                X = _aes.EncryptBlock(key, XorUtils.Xor(X, blocks[i]));
            }

            // Step 4: Final block
            byte[] T = _aes.EncryptBlock(key, XorUtils.Xor(X, lastBlock));

            return T;
        }

        /// <summary>
        /// Generates AES-CMAC subkeys K1 and K2 according to RFC 4493.
        /// </summary>
        private (byte[] K1, byte[] K2) GenerateSubkeys(byte[] key)
        {
            // Step 1: L = AES-128(key, 0^128)
            byte[] L = _aes.EncryptBlock(key, new byte[16]);

            // Step 2: K1 = L << 1 (with Rb if MSB=1)
            byte[] K1 = LeftShiftOneBit(L);
            if ((L[0] & 0x80) != 0)
                K1[15] ^= 0x87; // Rb constant

            // Step 3: K2 = K1 << 1 (with Rb if MSB=1)
            byte[] K2 = LeftShiftOneBit(K1);
            if ((K1[0] & 0x80) != 0)
                K2[15] ^= 0x87;

            return (K1, K2);
        }

        /// <summary>
        /// Performs a 128-bit left shift by one bit.
        /// </summary>
        private static byte[] LeftShiftOneBit(byte[] input)
        {
            var output = new byte[input.Length];
            byte carry = 0;

            for (int i = input.Length - 1; i >= 0; i--)
            {
                byte newCarry = (byte)((input[i] & 0x80) != 0 ? 1 : 0);
                output[i] = (byte)((input[i] << 1) | carry);
                carry = newCarry;
            }

            return output;
        }
    }
}
