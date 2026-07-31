// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// EMV Engine: Provides DES/3DES AC Session Key derivation (SK_AC) using ATC diversification.

using System;
using SecretArqc.Core.Primitives;
using SecretArqc.Core.Crypto;

namespace SecretArqc.Core.Emv.SessionKeyDerivation
{
    /// <summary>
    /// Implements EMV DES/3DES AC Session Key derivation.
    /// Produces SK_AC from:
    /// - ICC Master Key (IMK-AC)
    /// - Application Transaction Counter (ATC)
    /// 
    /// This session key is used for ARQC and ARPC generation.
    /// </summary>
    public class DesSessionKeyDeriver
    {
        private readonly TripleDesEngine _tdes = new TripleDesEngine();

        /// <summary>
        /// Derives the AC Session Key (SK_AC) using EMV 3DES ATC diversification.
        /// </summary>
        /// <param name="iccMasterKey">The ICC Master Key (IMK-AC).</param>
        /// <param name="atcHex">ATC in hex (2 bytes).</param>
        /// <returns>Derived SK_AC.</returns>
        public byte[] Derive(byte[] iccMasterKey, string atcHex)
        {
            if (iccMasterKey == null || iccMasterKey.Length != 16)
                throw new ArgumentException("ICC Master Key (MK-AC) must be 16 bytes.");

            if (string.IsNullOrWhiteSpace(atcHex))
                throw new ArgumentNullException(nameof(atcHex));

            // ATC: 2 bytes
            byte[] atc = HexUtils.FromHex(atcHex);
            if (atc.Length != 2)
                throw new ArgumentException("ATC must be exactly 2 bytes.");

            // Build two diversification blocks (MUST be 8 bytes for 3DES):
            // B1 = ATC || 0xF0 || 0x00 || 0x00 || 0x00 || 0x00 || 0x00
            // B2 = ATC || 0x0F || 0x00 || 0x00 || 0x00 || 0x00 || 0x00
            byte[] block1 = ConcatUtils.Concat(
                atc,
                new byte[] { 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00 } // 6 bytes padding
            );

            byte[] block2 = ConcatUtils.Concat(
                atc,
                new byte[] { 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00 } // 6 bytes padding
            );

            // Encrypt both blocks with MK-AC
            byte[] left = _tdes.EncryptBlock(iccMasterKey, block1); // 8 bytes
            byte[] right = _tdes.EncryptBlock(iccMasterKey, block2); // 8 bytes

            // Session key SK_AC = left || right (16 bytes)
            return ConcatUtils.Concat(left, right);
        }

    }
}
