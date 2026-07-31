// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Crypto Engine: Implements EMV Retail MAC (ISO 9797-1 Algorithm 3).

using System;
using System.Security.Cryptography;
using SecretArqc.Core.Primitives;

namespace SecretArqc.Core.Crypto
{
    /// <summary>
    /// Provides EMV Retail MAC generation using ISO 9797-1 Algorithm 3.
    /// Algorithm: DES-CBC with K1, then apply E(K1, D(K2, MAC)).
    /// Used in EMV ARQC, ARPC, and other MAC-based cryptographic flows.
    /// </summary>
    public class RetailMacEngine
    {
        /// <summary>
        /// Computes EMV Retail MAC per ISO 9797-1 Algorithm 3:
        /// 1. DES-CBC with K1 on all blocks
        /// 2. DES-decrypt result with K2
        /// 3. DES-encrypt result with K1
        /// </summary>
        public byte[] ComputeMac(byte[] key, byte[] iv, byte[] data)
        {
            if (key == null || iv == null || data == null)
                throw new ArgumentNullException();

            if (iv.Length != 8)
                throw new ArgumentException("IV must be 8 bytes.");

            if (key.Length != 16 && key.Length != 24)
                throw new ArgumentException("Key must be 16 or 24 bytes for 3DES.");

            // Step 1: Apply ISO9797-1 Padding Method 2
            var padded = PaddingUtils.Iso9797M2(data, 8);

            // Step 2: Extract K1 (left 8 bytes) and K2 (right 8 bytes)
            byte[] k1 = new byte[8];
            byte[] k2 = new byte[8];
            Array.Copy(key, 0, k1, 0, 8);
            Array.Copy(key, 8, k2, 0, 8);

            // Step 3: DES-CBC with K1 on all blocks
            byte[] intermediateMac = (byte[])iv.Clone();
            
            using (var des = DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;
                des.Key = k1;

                using var encryptor = des.CreateEncryptor();

                for (int i = 0; i < padded.Length; i += 8)
                {
                    byte[] block = new byte[8];
                    Array.Copy(padded, i, block, 0, 8);

                    // XOR with previous (CBC mode)
                    for (int j = 0; j < 8; j++)
                    {
                        intermediateMac[j] ^= block[j];
                    }

                    // Encrypt with single DES (K1)
                    intermediateMac = encryptor.TransformFinalBlock(intermediateMac, 0, 8);
                }
            }

            // Step 4: Apply E(K1, D(K2, intermediateMac)) to convert to 3DES-EDE
            byte[] finalMac;
            
            using (var des = DES.Create())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;
                
                // Decrypt with K2
                des.Key = k2;
                using (var decryptor = des.CreateDecryptor())
                {
                    finalMac = decryptor.TransformFinalBlock(intermediateMac, 0, 8);
                }
                
                // Encrypt with K1
                des.Key = k1;
                using (var encryptor = des.CreateEncryptor())
                {
                    finalMac = encryptor.TransformFinalBlock(finalMac, 0, 8);
                }
            }

            return finalMac;
        }
    }
}