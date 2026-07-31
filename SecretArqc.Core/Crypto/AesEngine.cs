// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Crypto Engine: Provides EMV‑safe AES encryption and decryption utilities.

using System;
using System.Security.Cryptography;

namespace SecretArqc.Core.Crypto
{
    /// <summary>
    /// Provides AES encryption and decryption operations used throughout EMV processing,
    /// including AES Option 3 key derivation, AES CMAC, and secure messaging flows.
    /// </summary>
    public class AesEngine
    {
        /// <summary>
        /// Encrypts a single 16‑byte block using AES‑128 ECB mode.
        /// </summary>
        public byte[] EncryptBlock(byte[] key, byte[] block)
        {
            if (key == null || block == null)
                throw new ArgumentNullException();

            if (block.Length != 16)
                throw new ArgumentException("Block must be exactly 16 bytes.");

            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(block, 0, 16);
        }

        /// <summary>
        /// Decrypts a single 16‑byte block using AES‑128 ECB mode.
        /// </summary>
        public byte[] DecryptBlock(byte[] key, byte[] block)
        {
            if (key == null || block == null)
                throw new ArgumentNullException();

            if (block.Length != 16)
                throw new ArgumentException("Block must be exactly 16 bytes.");

            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(block, 0, 16);
        }

        /// <summary>
        /// Encrypts data using AES CBC mode with the given IV.
        /// Padding is assumed to be handled externally (EMV uses ISO9797‑1 M2).
        /// </summary>
        public byte[] EncryptCbc(byte[] key, byte[] iv, byte[] data)
        {
            if (key == null || iv == null || data == null)
                throw new ArgumentNullException();

            if (iv.Length != 16)
                throw new ArgumentException("IV must be 16 bytes.");

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        /// <summary>
        /// Decrypts data using AES CBC mode with the given IV.
        /// Padding is assumed to be handled externally.
        /// </summary>
        public byte[] DecryptCbc(byte[] key, byte[] iv, byte[] data)
        {
            if (key == null || iv == null || data == null)
                throw new ArgumentNullException();

            if (iv.Length != 16)
                throw new ArgumentException("IV must be 16 bytes.");

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }
}
