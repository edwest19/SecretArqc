// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// EMV Engine: Generates ARQC (Authorization Request Cryptogram) using EMV 3DES SK_AC session keys.

using SecretArqc.Core.Crypto;
using SecretArqc.Core.Emv.SessionKeyDerivation;
using SecretArqc.Core.Primitives;
using SecretArqc.Core.Models;
using System;

namespace SecretArqc.Core.Emv.Arqc
{
    /// <summary>
    /// Implements EMV ARQC generation (3DES variant).
    /// Uses:
    /// - SK_AC (session key derived from IMK-AC + ATC)
    /// - EMV Retail MAC (ISO 9797-1 Algorithm 3)
    /// - EMV data fields (UN, ATC, AIP, AFL, etc.)
    /// 
    /// Produces the ARQC sent to the issuer for online authorization.
    /// </summary>
    public class ArqcEngine
    {
        private readonly RetailMacEngine _mac = new RetailMacEngine();
        private readonly DesSessionKeyDeriver _sessionKeyDeriver = new DesSessionKeyDeriver();

        /// <summary>
        /// Generates ARQC using EMV 3DES Retail MAC.
        /// </summary>
        /// <param name="iccMasterKey">IMK-AC (ICC Master Key for AC).</param>
        /// <param name="atcHex">ATC in hex (2 bytes).</param>
        /// <param name="unHex">Unpredictable Number (UN) in hex.</param>
        /// <param name="transactionData">Full EMV transaction data block (DOL result).</param>
        /// <returns>ARQC (8-byte cryptogram).</returns>
        public byte[] GenerateArqc(byte[] iccMasterKey, string atcHex, string unHex, byte[] transactionData)
        {
            if (iccMasterKey == null)
                throw new ArgumentNullException(nameof(iccMasterKey));

            if (string.IsNullOrWhiteSpace(atcHex))
                throw new ArgumentNullException(nameof(atcHex));

            if (string.IsNullOrWhiteSpace(unHex))
                throw new ArgumentNullException(nameof(unHex));

            if (transactionData == null)
                throw new ArgumentNullException(nameof(transactionData));

            // Step 1: Derive SK_AC from IMK-AC + ATC
            byte[] skAc = _sessionKeyDeriver.Derive(iccMasterKey, atcHex);

            // Step 2: Convert UN to bytes
            byte[] un = HexUtils.FromHex(unHex);

            // Step 3: Build MAC input: UN || transactionData
            byte[] macInput = ConcatUtils.Concat(un, transactionData);

            // Step 4: Compute ARQC using Retail MAC (3DES CBC)
            // IV = 0x00...00 (EMV standard)
            byte[] iv = new byte[8];

            byte[] arqc = _mac.ComputeMac(skAc, iv, macInput);

            return arqc;
        }

        public ArqcResult GenerateArqc(
            string sessionKeyHex,
            byte[] dolBytes,
            byte[] tagValuesBytes
        )
        {
            byte[] sessionKey = Convert.FromHexString(sessionKeyHex);

            // DOL is only used to validate structure, not included in MAC
            // MAC input is ONLY the concatenated tag values
            byte[] macInput = tagValuesBytes;

            byte[] iv = new byte[8]; // EMV IV = 0x00...00

            var mac = new RetailMacEngine();
            byte[] arqc = mac.ComputeMac(sessionKey, iv, macInput);

            return new ArqcResult
            {
                Arqc = Convert.ToHexString(arqc)
            };
        }
    }
}
