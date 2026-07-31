// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// EMV Engine: Provides AES AC Session Key derivation (SK_AC) using ATC diversification.

using System;
using SecretArqc.Core.Primitives;
using SecretArqc.Core.Crypto;

namespace SecretArqc.Core.Emv.SessionKeyDerivation
{
    /// <summary>
    /// Implements EMV AES AC Session Key derivation (AES Option 3).
    /// Produces SK_AC from:
    /// - ICC Master Key (IMK-AES)
    /// - Application Transaction Counter (ATC)
    /// 
    /// This session key is used for AES-based ARQC and ARPC generation.
    /// </summary>
    public class AesSessionKeyDeriver
    {
        private readonly AesCmacEngine _cmac = new AesCmacEngine();

        /// <summary>
        /// Derives the AC Session Key (SK_AC) using EMV AES ATC diversification.
        /// </summary>
        /// <param name="iccMasterKey">The ICC Master Key (IMK-AES).</param>
        /// <param name="atcHex">ATC in hex (2 bytes).</param>
        /// <returns>Derived AES SK_AC.</returns>
        public byte[] Derive(byte[] iccMasterKey, string atcHex)
        {
            if (iccMasterKey == null || iccMasterKey.Length != 16)
                throw new ArgumentException("ICC Master Key (IMK-AES) must be 16 bytes.");

            if (string.IsNullOrWhiteSpace(atcHex))
                throw new ArgumentNullException(nameof(atcHex));

            // ATC must be 2 bytes
            byte[] atc = HexUtils.FromHex(atcHex);
            if (atc.Length != 2)
                throw new ArgumentException("ATC must be exactly 2 bytes.");

            // Build 16-byte diversification block:
            // ATC (2 bytes) + 14 bytes of 0x00
            byte[] diversificationData = BuildDiversificationBlock(atc);

            // EMV AES Option 3:
            // SK_AC = AES-CMAC(IMK-AES, diversificationData)
            byte[] sessionKey = _cmac.ComputeCmac(iccMasterKey, diversificationData);

            return sessionKey; // 16-byte AES session key
        }

        /// <summary>
        /// Builds the EMV ATC diversification block for AES SK_AC.
        /// </summary>
        private byte[] BuildDiversificationBlock(byte[] atc)
        {
            // Standard AES pattern (issuer-specific variants exist):
            // ATC (2 bytes) + 14 bytes of 0x00
            return ConcatUtils.Concat(
                atc,
                new byte[14] // 14 zero bytes
            );
        }
    }
}
