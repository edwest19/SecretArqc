// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// EMV Engine: Generates ARPC (Authorization Response Cryptogram) from ARQC using issuer 3DES keys.

using SecretArqc.Core.Crypto;
using SecretArqc.Core.Primitives;
using SecretArqc.Core.Models;
using System;

namespace SecretArqc.Core.Emv.Arpc
{
    /// <summary>
    /// Implements EMV ARPC generation (3DES variant).
    /// Supports:
    /// - Method 1: ARPC = 3DES(SK_ARPC, ARQC XOR ARC)
    /// - Method 2: ARPC = MAC4(SK_AC, ARQC || CSU) - EMV 4.3 Book 2 A.3.4
    /// 
    /// SK_ARPC is typically derived from issuer keys; this class focuses on
    /// the cryptogram transformation itself.
    /// </summary>
    public class ArpcEngine
    {
        private readonly TripleDesEngine _tdes = new TripleDesEngine();
        private readonly RetailMacEngine _mac = new RetailMacEngine();

        /// <summary>
        /// Generates ARPC using EMV Method 1:
        /// ARPC = 3DES(SK_ARPC, ARQC XOR ARC)
        /// </summary>
        /// <param name="arqc">ARQC (8 bytes).</param>
        /// <param name="arc">Authorization Response Code (2 bytes, hex string).</param>
        /// <param name="sessionKey">SK_ARPC (3DES key bytes).</param>
        /// <returns>ARPC (8-byte cryptogram).</returns>
        public byte[] GenerateMethod1(byte[] arqc, string arc, byte[] sessionKey)
        {
            if (arqc == null)
                throw new ArgumentNullException(nameof(arqc));

            if (sessionKey == null)
                throw new ArgumentNullException(nameof(sessionKey));

            if (arqc.Length != 8)
                throw new ArgumentException("ARQC must be exactly 8 bytes.");

            if (string.IsNullOrWhiteSpace(arc))
                throw new ArgumentNullException(nameof(arc));

            // ARC is 2 bytes; pad to 8 bytes as per issuer profile (ARC || 0x00...00)
            byte[] arcBytes = HexUtils.FromHex(arc);
            if (arcBytes.Length != 2)
                throw new ArgumentException("ARC must be exactly 2 bytes.");

            byte[] arcBlock = ConcatUtils.Concat(arcBytes, new byte[6]); // 2 + 6 = 8

            // ARQC XOR ARC-block
            byte[] input = XorUtils.Xor(arqc, arcBlock);

            // ARPC = 3DES(SK_ARPC, input)
            return _tdes.EncryptBlock(sessionKey, input);
        }

        /// <summary>
        /// Generates ARPC using EMV 4.3 Book 2 Method (A.3.4):
        /// ARPC = MAC4(SK_AC, ARQC || CSU)
        /// Returns first 4 bytes of the MAC.
        /// </summary>
        /// <param name="arqc">ARQC (8 bytes).</param>
        /// <param name="csu">Card Status Update (4 bytes).</param>
        /// <param name="sessionKey">SK_AC (3DES key bytes).</param>
        /// <returns>ARPC (4-byte cryptogram).</returns>
        public byte[] GenerateWithCSU(byte[] arqc, byte[] csu, byte[] sessionKey)
        {
            if (arqc == null)
                throw new ArgumentNullException(nameof(arqc));

            if (csu == null)
                throw new ArgumentNullException(nameof(csu));

            if (sessionKey == null)
                throw new ArgumentNullException(nameof(sessionKey));

            if (arqc.Length != 8)
                throw new ArgumentException("ARQC must be exactly 8 bytes.");

            if (csu.Length != 4)
                throw new ArgumentException("CSU must be exactly 4 bytes.");

            // Concatenate ARQC || CSU
            byte[] input = ConcatUtils.Concat(arqc, csu);

            // Compute MAC using Retail MAC
            byte[] iv = new byte[8]; // Zero IV
            byte[] mac = _mac.ComputeMac(sessionKey, iv, input);

            // Return first 4 bytes (MAC4)
            byte[] arpc = new byte[4];
            Array.Copy(mac, 0, arpc, 0, 4);

            return arpc;
        }

        public ArpcResult GenerateArpc(string arqcHex, string arcHex, string sessionKeyHex)
        {
            // Convert inputs
            byte[] arqc = Convert.FromHexString(arqcHex);
            byte[] sessionKey = Convert.FromHexString(sessionKeyHex);

            // Validate
            if (arqc.Length != 8)
                throw new ArgumentException("ARQC must be 8 bytes.");

            // Check if ARC is actually CSU (4 bytes) or traditional ARC (2 bytes)
            byte[] arcBytes = Convert.FromHexString(arcHex);
            
            if (arcBytes.Length == 4)
            {
                // EMV 4.3 Book 2 Method: MAC4(SK_AC, ARQC || CSU)
                byte[] arpc = GenerateWithCSU(arqc, arcBytes, sessionKey);
                return new ArpcResult
                {
                    Arpc = Convert.ToHexString(arpc)
                };
            }
            else if (arcBytes.Length == 2)
            {
                // Traditional Method 1: ARPC = 3DES(SK_AC, ARQC XOR (ARC || 00 00 00 00 00 00))
                byte[] arcPadded = new byte[8];
                Array.Copy(arcBytes, 0, arcPadded, 0, 2);

                // XOR ARQC with padded ARC
                byte[] xored = new byte[8];
                for (int i = 0; i < 8; i++)
                    xored[i] = (byte)(arqc[i] ^ arcPadded[i]);

                // Encrypt with session key
                byte[] arpc = _tdes.EncryptBlock(sessionKey, xored);

                return new ArpcResult
                {
                    Arpc = Convert.ToHexString(arpc)
                };
            }
            else
            {
                throw new ArgumentException("ARC/CSU must be 2 bytes (ARC) or 4 bytes (CSU).");
            }
        }

        /// <summary>
        /// Generates ARPC using EMV Method 2:
        /// ARPC = 3DES(SK_ARPC, ARQC) XOR ARC
        /// </summary>
        /// <param name="arqc">ARQC (8 bytes).</param>
        /// <param name="arc">Authorization Response Code (2 bytes, hex string).</param>
        /// <param name="sessionKey">SK_ARPC (3DES key bytes).</param>
        /// <returns>ARPC (8-byte cryptogram).</returns>
        public byte[] GenerateMethod2(byte[] arqc, string arc, byte[] sessionKey)
        {
            if (arqc == null)
                throw new ArgumentNullException(nameof(arqc));

            if (sessionKey == null)
                throw new ArgumentNullException(nameof(sessionKey));

            if (arqc.Length != 8)
                throw new ArgumentException("ARQC must be exactly 8 bytes.");

            if (string.IsNullOrWhiteSpace(arc))
                throw new ArgumentNullException(nameof(arc));

            // ARC is 2 bytes; pad to 8 bytes as per issuer profile (ARC || 0x00...00)
            byte[] arcBytes = HexUtils.FromHex(arc);
            if (arcBytes.Length != 2)
                throw new ArgumentException("ARC must be exactly 2 bytes.");

            byte[] arcBlock = ConcatUtils.Concat(arcBytes, new byte[6]); // 2 + 6 = 8

            // First: Y = 3DES(SK_ARPC, ARQC)
            byte[] y = _tdes.EncryptBlock(sessionKey, arqc);

            // ARPC = Y XOR ARC-block
            return XorUtils.Xor(y, arcBlock);
        }
    }
}
