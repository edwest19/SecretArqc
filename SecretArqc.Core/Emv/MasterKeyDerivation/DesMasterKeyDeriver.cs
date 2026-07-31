// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// EMV Engine: Provides DES/3DES ICC Master Key derivation (Option A and Option B).

using System;
using SecretArqc.Core.Primitives;
using SecretArqc.Core.Crypto;

namespace SecretArqc.Core.Emv.MasterKeyDerivation
{
    /// <summary>
    /// Implements EMV DES/3DES ICC Master Key derivation.
    /// Supports:
    /// - Option A (PAN decimalisation)
    /// - Option B (PAN block method)
    /// 
    /// This class produces the ICC Master Key (IMK) used for session key derivation.
    /// </summary>
    public class DesMasterKeyDeriver
    {
        private readonly TripleDesEngine _tdes = new TripleDesEngine();

        /// <summary>
        /// Derives the ICC Master Key using EMV Option A (PAN decimalisation).
        /// </summary>
        /// <param name="issuerMasterKey">The issuer master key (IMK).</param>
        /// <param name="pan">Primary Account Number (PAN).</param>
        /// <param name="sequenceNumber">Card sequence number (CSN).</param>
        /// <returns>Derived ICC Master Key (16 bytes for 3DES).</returns>
        public byte[] DeriveOptionA(byte[] imk, string pan, string psn)
        {
            if (imk == null || imk.Length != 16)
                throw new ArgumentException("IMK-AC must be 16 bytes.");

            if (string.IsNullOrWhiteSpace(pan))
                throw new ArgumentNullException(nameof(pan));

            if (string.IsNullOrWhiteSpace(psn))
                throw new ArgumentNullException(nameof(psn));

            // 1. Take rightmost 14 hex digits (7 bytes) of PAN
            string pan14 = pan.Length > 14 ? pan.Substring(pan.Length - 14) : pan.PadLeft(14, '0');

            // 2. Append 2-digit PSN (1 byte) to form 8-byte diversification block
            string psn2 = psn.Length >= 2 ? psn.Substring(psn.Length - 2) : psn.PadLeft(2, '0');
            string diversificationHex = pan14 + psn2;

            byte[] diversificationData = Convert.FromHexString(diversificationHex);

            if (diversificationData.Length != 8)
                throw new Exception("Diversification data must be exactly 8 bytes.");

            // 3. Derive left half: K1 = 3DES(IMK-AC, Input)
            var tdes = new TripleDesEngine();
            byte[] k1 = tdes.EncryptBlock(imk, diversificationData);

            // 4. Derive right half: K2 = 3DES(IMK-AC, Input XOR FFFFFFFFFFFFFFFF)
            byte[] xorData = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                xorData[i] = (byte)(diversificationData[i] ^ 0xFF);
            }
            byte[] k2 = tdes.EncryptBlock(imk, xorData);

            // 5. Concatenate K1 and K2 to form 16-byte master key
            byte[] mkac = new byte[16];
            Array.Copy(k1, 0, mkac, 0, 8);
            Array.Copy(k2, 0, mkac, 8, 8);

            // 6. Apply DES odd parity to each byte (EMVCo requirement)
            ApplyDesOddParity(mkac);

            return mkac;
        }
        /// <summary>
        /// Derives the ICC Master Key using EMV Option B (PAN block method).
        /// </summary>
        /// <param name="issuerMasterKey">The issuer master key (IMK).</param>
        /// <param name="pan">Primary Account Number (PAN).</param>
        /// <param name="sequenceNumber">Card sequence number (CSN).</param>
        /// <returns>Derived ICC Master Key (16 bytes for 3DES).</returns>
        public byte[] DeriveOptionB(byte[] issuerMasterKey, string pan, string sequenceNumber)
        {
            if (issuerMasterKey == null || issuerMasterKey.Length != 16)
                throw new ArgumentException("IMK-AC must be 16 bytes.");

            if (string.IsNullOrWhiteSpace(pan))
                throw new ArgumentNullException(nameof(pan));

            if (string.IsNullOrWhiteSpace(sequenceNumber))
                throw new ArgumentNullException(nameof(sequenceNumber));

            // 1. Take rightmost 16 digits of PAN
            string pan16 = pan.Length > 16 ? pan.Substring(pan.Length - 16) : pan;

            if (pan16.Length != 16)
                throw new ArgumentException("PAN must contain at least 16 digits.");

            // Convert PAN16 to bytes (8 bytes)
            byte[] panBlock = Convert.FromHexString(pan16);

            // 2. Extract PSN nibble (last hex digit)
            char psnNibbleChar = sequenceNumber[sequenceNumber.Length - 1];

            // Validate nibble
            if (!Uri.IsHexDigit(psnNibbleChar))
                throw new ArgumentException("PSN must be hex.");

            // Convert nibble to value
            byte psnNibble = Convert.ToByte(psnNibbleChar.ToString(), 16);

            // 3. Pad nibble with F (EMV Option B rule)
            byte paddedNibble = (byte)((psnNibble << 4) | 0x0F);

            // 4. First 3DES encryption: K1 = 3DES(IMK, PAN16)
            var tdes = new TripleDesEngine();
            byte[] k1 = tdes.EncryptBlock(issuerMasterKey, panBlock);

            // 5. XOR last byte of K1 with padded nibble
            byte[] k1Modified = (byte[])k1.Clone();
            k1Modified[k1Modified.Length - 1] ^= paddedNibble;

            // 6. Derive left half: use modified K1 as data
            byte[] leftHalf = tdes.EncryptBlock(issuerMasterKey, k1Modified);

            // 7. Derive right half: invert k1Modified and encrypt
            byte[] k1Inverted = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                k1Inverted[i] = (byte)~k1Modified[i];
            }
            byte[] rightHalf = tdes.EncryptBlock(issuerMasterKey, k1Inverted);

            // 8. Concatenate to form 16-byte master key
            byte[] mkac = new byte[16];
            Array.Copy(leftHalf, 0, mkac, 0, 8);
            Array.Copy(rightHalf, 0, mkac, 8, 8);

            // 9. Apply DES odd parity (EMVCo requirement)
            ApplyDesOddParity(mkac);

            return mkac;
        }

        /// <summary>
        /// Builds the PAN block used in EMV Option B.
        /// </summary>
        private string BuildPanBlock(string pan)
        {
            // Rightmost 16 digits of PAN (excluding check digit)
            string trimmed = pan.Length > 16
                ? pan.Substring(pan.Length - 16)
                : pan;

            return trimmed;
        }
        /// <summary>
        /// Applies DES odd parity to each byte of the key.
        /// Sets the least significant bit of each byte to ensure an odd number of 1-bits.
        /// This is required by the EMVCo specification for derived keys.
        /// </summary>
        private static void ApplyDesOddParity(byte[] key)
        {
            for (int i = 0; i < key.Length; i++)
            {
                byte b = key[i];
                // Count the number of 1-bits in the upper 7 bits
                int bitCount = 0;
                for (int j = 1; j < 8; j++)
                {
                    if ((b & (1 << j)) != 0)
                        bitCount++;
                }

                // Set LSB to make total count odd
                if (bitCount % 2 == 0)
                    key[i] = (byte)(b | 0x01);  // Set LSB to 1
                else
                    key[i] = (byte)(b & 0xFE);  // Clear LSB to 0
            }
        }
    }
}