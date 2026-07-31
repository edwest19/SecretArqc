// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// EMV Engine: Provides AES ICC Master Key derivation (AES Option 3).

using System;
using SecretArqc.Core.Primitives;
using SecretArqc.Core.Crypto;

namespace SecretArqc.Core.Emv.MasterKeyDerivation
{
    /// <summary>
    /// Implements EMV AES ICC Master Key derivation (AES Option 3).
    /// Produces the AES ICC Master Key (IMK-AES) used for AES session key derivation.
    /// </summary>
    public class AesMasterKeyDeriver
    {
        private readonly AesCmacEngine _cmac = new AesCmacEngine();

        /// <summary>
        /// Derives the ICC Master Key using EMV AES Option 3.
        /// </summary>
        /// <param name="issuerMasterKey">The issuer AES master key (IMK-AES).</param>
        /// <param name="pan">Primary Account Number (PAN).</param>
        /// <param name="sequenceNumber">Card sequence number (CSN).</param>
        /// <returns>Derived AES ICC Master Key.</returns>
        public byte[] Derive(byte[] issuerMasterKey, string pan, string sequenceNumber)
        {
            if (issuerMasterKey == null)
                throw new ArgumentNullException(nameof(issuerMasterKey));

            if (pan == null || sequenceNumber == null)
                throw new ArgumentNullException();

            // Build PAN16: rightmost 16 digits of PAN (EMV rule)
            string pan16 = pan.Length > 16 ? pan.Substring(pan.Length - 16) : pan;
            if (pan16.Length != 16)
                throw new ArgumentException("PAN must contain at least 16 digits.");

            // Convert PAN16 (hex/decimal digits 0-9) to bytes (BCD-like hex pairs)
            byte[] panBytes = Convert.FromHexString(pan16);

            // Build 16-byte diversification block per README: PAN16 || 14x00
            // NOTE: PAN16 -> panBytes (typically 8 bytes), concatenated with 14 zeros produces a variable-length
            // message for CMAC. AES-CMAC accepts arbitrary-length messages; this follows the project's README rule.
            byte[] diversificationData = ConcatUtils.Concat(panBytes, new byte[14]);

            // AES Option 3: MK_AC = AES-CMAC(IMK-AES, diversification_block)
            byte[] derived = _cmac.ComputeCmac(issuerMasterKey, diversificationData);

            return derived;
        }
    }
}
