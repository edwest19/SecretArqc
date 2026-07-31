// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Crypto Engine: Provides EMV‑safe Triple DES (3DES) encryption and decryption utilities.

using System;
using System.Security.Cryptography;

namespace SecretArqc.Core.Crypto
{
    /// <summary>
    /// Provides Triple DES (3DES) encryption and decryption operations
    /// used throughout EMV cryptographic processing including:
    /// - Retail MAC
    /// - ARQC/ARPC generation
    /// - Master/session key derivation (Option A/B)
    /// </summary>
    public class TripleDesEngine
    {
        /// <summary>
        /// Encrypts a single 8‑byte block using 3DES ECB mode.
        /// </summary>
        public byte[] EncryptBlock(byte[] key, byte[] block)
        {
            if (key == null || block == null)
                throw new ArgumentNullException();

            if (block.Length != 8)
                throw new ArgumentException("Block must be exactly 8 bytes.");

            using var tdes = TripleDES.Create();
            tdes.Key = key;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.None;

            using var encryptor = tdes.CreateEncryptor();
            return encryptor.TransformFinalBlock(block, 0, 8);
        }

        /// <summary>
        /// Decrypts a single 8‑byte block using 3DES ECB mode.
        /// </summary>
        public byte[] DecryptBlock(byte[] key, byte[] block)
        {
            if (key == null || block == null)
                throw new ArgumentNullException();

            if (block.Length != 8)
                throw new ArgumentException("Block must be exactly 8 bytes.");

            using var tdes = TripleDES.Create();
            tdes.Key = key;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.None;

            using var decryptor = tdes.CreateDecryptor();
            return decryptor.TransformFinalBlock(block, 0, 8);
        }

        /// <summary>
        /// Encrypts data using 3DES CBC mode with the given IV.
        /// Padding is assumed to be handled externally (EMV uses ISO9797‑1 M2).
        /// </summary>
        public byte[] EncryptCbc(byte[] key, byte[] iv, byte[] data)
        {
            if (key == null || iv == null || data == null)
                throw new ArgumentNullException();

            if (iv.Length != 8)
                throw new ArgumentException("IV must be 8 bytes.");

            using var tdes = TripleDES.Create();
            tdes.Key = key;
            tdes.IV = iv;
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.None;

            using var encryptor = tdes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        /// <summary>
        /// Decrypts data using 3DES CBC mode with the given IV.
        /// Padding is assumed to be handled externally.
        /// </summary>
        public byte[] DecryptCbc(byte[] key, byte[] iv, byte[] data)
        {
            if (key == null || iv == null || data == null)
                throw new ArgumentNullException();

            if (iv.Length != 8)
                throw new ArgumentException("IV must be 8 bytes.");

            using var tdes = TripleDES.Create();
            tdes.Key = key;
            tdes.IV = iv;
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.None;

            using var decryptor = tdes.CreateDecryptor();
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }
}
