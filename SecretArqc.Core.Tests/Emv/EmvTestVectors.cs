// Copyright (c) 2026 edwest19
// All rights reserved.
// Ported from SecretEmv.Core.Tests.
//
// NOTE ON NAMING: these tests were originally labeled things like "EMV Book 2
// Test Vector" / "Mastercard Test Vector" / "Visa Test Vector", which implies
// each assertion checks output against a known-correct value published by
// that source. In fact almost every assertion here only checks shape
// (length), non-emptiness, or determinism/uniqueness across repeated calls -
// none of them compare against an actual published expected value. Renamed
// to describe what's actually verified. The tests in
// EmvCryptoPipelineServiceTests.cs that DO check real EMV 4.3 Book 2 spec
// values (e.g. GenerateArqc_MatchesEmvSpecA33) are the ones that earn that
// label.
using Xunit;
using SecretArqc.Core.Emv;
using System;

namespace SecretArqc.Core.Tests.Emv
{
    public class EmvTestVectors
    {
        private readonly EmvCryptoPipelineService _service;

        public EmvTestVectors()
        {
            _service = new EmvCryptoPipelineService();
        }

        #region Master Key Derivation - Shape/Determinism Checks

        [Fact]
        public void MasterKeyDerivation_OptionA_ProducesConsistentLength()
        {
            var imkAc = HexToBytes("0123456789ABCDEFFEDCBA9876543210");
            var pan = "5123456789012345";
            var psn = "00";

            var mkAc = _service.DeriveDesIccMasterKeyOptionA(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.Equal(16, mkAc.Length); // 3DES key is 16 bytes (K1||K2)
            Assert.NotEmpty(BytesToHex(mkAc));
        }

        [Fact]
        public void MasterKeyDerivation_OptionA_ProducesConsistentLength_AlternateInput()
        {
            var imkAc = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var pan = "5413330089010020";
            var psn = "01";

            var mkAc = _service.DeriveDesIccMasterKeyOptionA(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.Equal(16, mkAc.Length);
            Assert.NotEmpty(BytesToHex(mkAc));
        }

        [Fact]
        public void MasterKeyDerivation_OptionB_ProducesConsistentLength()
        {
            var imkAc = HexToBytes("0123456789ABCDEFFEDCBA9876543210");
            var pan = "51234567890123456789"; // 20 digits
            var psn = "00";

            var mkAc = _service.DeriveDesIccMasterKeyOptionB(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.Equal(16, mkAc.Length);
            Assert.NotEmpty(BytesToHex(mkAc));
        }
        #endregion

        #region Session Key Derivation - Shape/Determinism Checks

        [Fact]
        public void SessionKeyDerivation_ProducesConsistentLength_ATC0001()
        {
            var mkAc = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var atc = "0001";

            var skAc = _service.DeriveDesSessionKey(mkAc, atc);

            Assert.NotNull(skAc);
            Assert.Equal(16, skAc.Length);
            Assert.NotEmpty(BytesToHex(skAc));
        }

        [Fact]
        public void SessionKeyDerivation_DifferentAtc_ProducesDifferentKey()
        {
            var mkAc = HexToBytes("ABCDEF01234567890123456789ABCDEF");
            var atc = "0017";

            var skAc = _service.DeriveDesSessionKey(mkAc, atc);

            Assert.NotNull(skAc);
            Assert.Equal(16, skAc.Length);

            var skAc2 = _service.DeriveDesSessionKey(mkAc, "0018");
            Assert.NotEqual(BytesToHex(skAc), BytesToHex(skAc2));
        }

        [Fact]
        public void SessionKeyDerivation_ProducesConsistentLength_ATC00FF()
        {
            var mkAc = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var atc = "00FF";

            var skAc = _service.DeriveDesSessionKey(mkAc, atc);

            Assert.NotNull(skAc);
            Assert.Equal(16, skAc.Length);
            Assert.NotEmpty(BytesToHex(skAc));
        }

        #endregion

        #region ARQC Generation - Shape/Determinism Checks

        [Fact]
        public void ArqcGeneration_IsDeterministic_MinimalDol()
        {
            var sessionKey = "FEDCBA98765432100123456789ABCDEF";
            var dol = HexToBytes("9F3704"); // CDOL: 9F37 04 (Unpredictable Number, 4 bytes)
            var transactionData = HexToBytes("12345678");

            var result = _service.GenerateArqc(sessionKey, dol, transactionData);

            Assert.NotNull(result);
            Assert.NotNull(result.Arqc);
            Assert.Equal(16, result.Arqc.Length); // 8 bytes = 16 hex chars

            var result2 = _service.GenerateArqc(sessionKey, dol, transactionData);
            Assert.Equal(result.Arqc, result2.Arqc);
        }

        [Fact]
        public void ArqcGeneration_ProducesNonZeroOutput_StandardCdol1()
        {
            var sessionKey = "ABCDEF01234567890123456789ABCDEF";

            // Standard CDOL1 shape: 9F02 06 9F03 06 9F1A 02 95 05 5F2A 02 9A 03 9C 01 9F37 04
            var dol = HexToBytes("9F02069F03069F1A02950555F2A029A039C019F3704");

            var transactionData = HexToBytes(
                "000000010000" +  // 9F02: Amount Authorized = $100.00
                "000000000000" +  // 9F03: Amount Other = $0.00
                "0840" +          // 9F1A: Terminal Country Code = US (840)
                "0000000000" +    // 95:   TVR = All bits clear
                "0840" +          // 5F2A: Transaction Currency = USD (840)
                "241231" +        // 9A:   Transaction Date = 2024-12-31
                "00" +            // 9C:   Transaction Type = Purchase
                "87654321"        // 9F37: Unpredictable Number
            );

            var result = _service.GenerateArqc(sessionKey, dol, transactionData);

            Assert.NotNull(result);
            Assert.NotNull(result.Arqc);
            Assert.Equal(16, result.Arqc.Length);
            Assert.NotEqual("0000000000000000", result.Arqc);
        }

        [Fact]
        public void ArqcGeneration_ProducesValidLength_WithCvmResults()
        {
            var sessionKey = "FEDCBA98765432100123456789ABCDEF";

            // CDOL shape: 9F02 06 9F03 06 9F1A 02 95 05 5F2A 02 9A 03 9C 01 9F37 04 9F10 07
            var dol = HexToBytes("9F02069F03069F1A02950555F2A029A039C019F37049F1007");

            var transactionData = HexToBytes(
                "000000005000" +      // 9F02: Amount = $50.00
                "000000000000" +      // 9F03: Amount Other
                "0840" +              // 9F1A: Country Code
                "8000000000" +        // 95:   TVR (Offline PIN verification performed)
                "0840" +              // 5F2A: Currency
                "250101" +            // 9A:   Date = 2025-01-01
                "00" +                // 9C:   Type
                "ABCDEF01" +          // 9F37: UN
                "06010A03A00000"      // 9F10: Issuer Application Data (7 bytes)
            );

            var result = _service.GenerateArqc(sessionKey, dol, transactionData);

            Assert.NotNull(result);
            Assert.NotNull(result.Arqc);
            Assert.Equal(16, result.Arqc.Length);
        }

        #endregion

        #region ARPC Generation - Shape/Determinism Checks

        [Fact]
        public void ArpcGeneration_Method1_IsDeterministic()
        {
            var sessionKey = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var arqc = HexToBytes("1234567890ABCDEF"); // 8-byte ARQC
            var arc = "3030"; // ARC = "00" (Approved)

            var arpc = _service.GenerateArpcMethod1(sessionKey, arqc, arc);

            Assert.NotNull(arpc);
            Assert.Equal(8, arpc.Length);

            var arpc2 = _service.GenerateArpcMethod1(sessionKey, arqc, arc);
            Assert.Equal(BytesToHex(arpc), BytesToHex(arpc2));
        }

        [Fact]
        public void ArpcGeneration_Method1_ProducesCorrectLength_Approved()
        {
            var sessionKey = HexToBytes("ABCDEF01234567890123456789ABCDEF");
            var arqc = HexToBytes("FEDCBA9876543210");
            var arc = "3030"; // "00" = Approved

            var arpc = _service.GenerateArpcMethod1(sessionKey, arqc, arc);

            Assert.NotNull(arpc);
            Assert.Equal(8, arpc.Length);
            Assert.NotEmpty(BytesToHex(arpc));
        }

        [Fact]
        public void ArpcGeneration_Method1_DifferentArc_ProducesDifferentArpc()
        {
            var sessionKey = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var arqc = HexToBytes("0011223344556677");
            var arc = "3035"; // "05" = Declined

            var arpc = _service.GenerateArpcMethod1(sessionKey, arqc, arc);

            Assert.NotNull(arpc);
            Assert.Equal(8, arpc.Length);

            var arpc2 = _service.GenerateArpcMethod1(sessionKey, arqc, "3030");
            Assert.NotEqual(BytesToHex(arpc), BytesToHex(arpc2));
        }

        [Fact]
        public void ArpcGeneration_Method1And2_ProduceDifferentResults()
        {
            var sessionKey = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var arqc = HexToBytes("AABBCCDDEEFF0011");
            var arc = "3030";

            var arpc = _service.GenerateArpcMethod2(sessionKey, arqc, arc);

            Assert.NotNull(arpc);
            Assert.True(arpc.Length >= 8); // Method 2 can include additional data

            var arpcMethod1 = _service.GenerateArpcMethod1(sessionKey, arqc, arc);
            Assert.NotEqual(BytesToHex(arpcMethod1), BytesToHex(arpc));
        }

        #endregion

        #region Complete Transaction Flow (Integration Examples)

        [Fact]
        public void CompleteTransactionFlow_SessionKeyThroughArpc_Example1()
        {
            // Note: master key derivation returns 8 bytes but session key needs
            // 16 bytes, so this example focuses on session key -> ARQC -> ARPC.
            var mkAc16 = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var atc = "0042";

            var skAc = _service.DeriveDesSessionKey(mkAc16, atc);
            Assert.Equal(16, skAc.Length);

            var dol = HexToBytes("9F02069F03069F1A02950555F2A029A039C019F3704");
            var transactionData = HexToBytes(
                "000000002500" +  // $25.00
                "000000000000" +  // $0.00
                "0840" +          // US
                "0000000000" +    // TVR
                "0840" +          // USD
                "250115" +        // 2025-01-15
                "00" +            // Purchase
                "12345678"        // UN
            );

            var arqcResult = _service.GenerateArqc(BytesToHex(skAc), dol, transactionData);
            Assert.NotEmpty(arqcResult.Arqc);

            var arqcBytes = HexToBytes(arqcResult.Arqc);
            var arpc = _service.GenerateArpcMethod1(skAc, arqcBytes, "3030"); // Approved
            Assert.Equal(8, arpc.Length);
        }

        [Fact]
        public void CompleteTransactionFlow_SessionKeyThroughArpc_Example2()
        {
            var mkAc16 = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var atc = "0100";

            var skAc = _service.DeriveDesSessionKey(mkAc16, atc);

            var dol = HexToBytes("9F3704"); // Minimal for testing
            var transactionData = HexToBytes("DEADBEEF");

            var arqcResult = _service.GenerateArqc(BytesToHex(skAc), dol, transactionData);

            var arqcBytes = HexToBytes(arqcResult.Arqc);
            var arpc = _service.GenerateArpcMethod1(skAc, arqcBytes, "3030");

            Assert.NotNull(skAc);
            Assert.NotEmpty(arqcResult.Arqc);
            Assert.NotNull(arpc);
        }

        #endregion

        #region ATC Rollover and Edge Cases

        [Fact]
        public void SessionKeyDerivation_ATCRollover()
        {
            var mkAc = HexToBytes("FEDCBA98765432100123456789ABCDEF");

            var skFFFF = _service.DeriveDesSessionKey(mkAc, "FFFF");
            var sk0000 = _service.DeriveDesSessionKey(mkAc, "0000");
            var sk0001 = _service.DeriveDesSessionKey(mkAc, "0001");

            Assert.NotEqual(BytesToHex(skFFFF), BytesToHex(sk0000));
            Assert.NotEqual(BytesToHex(sk0000), BytesToHex(sk0001));
            Assert.NotEqual(BytesToHex(skFFFF), BytesToHex(sk0001));
        }

        [Fact]
        public void SessionKeyDerivation_MaximumATC()
        {
            var mkAc = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var atc = "FFFF"; // Maximum ATC value

            var skAc = _service.DeriveDesSessionKey(mkAc, atc);

            Assert.NotNull(skAc);
            Assert.Equal(16, skAc.Length);
        }

        #endregion

        #region Helper Methods

        private static byte[] HexToBytes(string hex)
        {
            hex = hex.Replace(" ", "").Replace("-", "");
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        private static string BytesToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        #endregion
    }
}
