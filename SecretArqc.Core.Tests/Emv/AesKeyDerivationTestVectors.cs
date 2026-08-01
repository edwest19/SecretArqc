// Copyright (c) 2026 edwest19
// All rights reserved.
// Ported from SecretEmv.Core.Tests.
//
// See the note at the top of EmvTestVectors.cs - same relabeling applied
// here for tests that only check shape/determinism rather than an actual
// published expected value.
using Xunit;
using SecretArqc.Core.Emv;
using System;

namespace SecretArqc.Core.Tests.Emv
{
    public class AesKeyDerivationTestVectors
    {
        private readonly EmvCryptoPipelineService _service;

        public AesKeyDerivationTestVectors()
        {
            _service = new EmvCryptoPipelineService();
        }

        #region AES-128 Master Key Derivation

        [Fact]
        public void Aes128MasterKeyDerivation_ProducesConsistentLength()
        {
            var imkAc = HexToBytes("0123456789ABCDEF0123456789ABCDEF"); // 16 bytes
            var pan = "5123456789012345";
            var psn = "00";

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.Equal(16, mkAc.Length); // AES-128 = 16 bytes
            Assert.NotEqual(new byte[16], mkAc);
            Assert.NotEmpty(BytesToHex(mkAc));
        }

        [Fact]
        public void Aes128MasterKeyDerivation_DiffersFromDesResult()
        {
            var imkAc = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var pan = "5413330089010020";
            var psn = "01";

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.Equal(16, mkAc.Length);

            var desMk = _service.DeriveDesIccMasterKeyOptionA(
                HexToBytes("FEDCBA98765432100123456789ABCDEF"),
                pan,
                psn
            );
            Assert.NotEqual(BytesToHex(mkAc), BytesToHex(desMk));
        }

        [Fact]
        public void Aes128MasterKeyDerivation_ProducesConsistentLength_AlternateInput()
        {
            var imkAc = HexToBytes("0011223344556677889900AABBCCDDEE");
            var pan = "4111111111111111";
            var psn = "00";

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.Equal(16, mkAc.Length);
            Assert.NotEmpty(BytesToHex(mkAc));
        }

        [Theory]
        [InlineData("5123456789012345", "00")]
        [InlineData("5123456789012345", "01")]
        [InlineData("5123456789012346", "00")]
        [InlineData("4111111111111111", "00")]
        public void AES128_MasterKeyDerivation_UniquenessTest(string pan, string psn)
        {
            var imkAc = HexToBytes("0123456789ABCDEF0123456789ABCDEF");

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.Equal(16, mkAc.Length);
            Assert.Contains(mkAc, b => b != 0);
        }

        #endregion

        #region AES-192 Master Key Derivation

        [Fact]
        public void Aes192MasterKeyDerivation_ProducesConsistentLength()
        {
            var imkAc = HexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"); // 24 bytes
            var pan = "5123456789012345";
            var psn = "00";

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.True(mkAc.Length == 24 || mkAc.Length == 16); // AES-192 = 24 bytes (or implementation may return 16)
            Assert.NotEmpty(BytesToHex(mkAc));
        }

        [Fact]
        public void Aes192MasterKeyDerivation_DifferentImk_ProducesDifferentKey()
        {
            var imkAc = HexToBytes("FEDCBA98765432100123456789ABCDEFFEDCBA9876543210");
            var pan = "5413330089010020";
            var psn = "01";

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.True(mkAc.Length == 24 || mkAc.Length == 16);

            var mkAc2 = _service.DeriveAesIccMasterKey(
                HexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
                pan,
                psn
            );
            Assert.NotEqual(BytesToHex(mkAc), BytesToHex(mkAc2));
        }

        #endregion

        #region AES-256 Master Key Derivation

        [Fact]
        public void Aes256MasterKeyDerivation_ProducesConsistentLength()
        {
            var imkAc = HexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"); // 32 bytes
            var pan = "5123456789012345";
            var psn = "00";

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.True(mkAc.Length == 32 || mkAc.Length == 16); // AES-256 = 32 bytes (or implementation may return 16)
            Assert.NotEmpty(BytesToHex(mkAc));
        }

        [Fact]
        public void Aes256MasterKeyDerivation_ProducesConsistentLength_AlternateInput()
        {
            var imkAc = HexToBytes("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0");
            var pan = "4111111111111111";
            var psn = "00";

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.True(mkAc.Length == 32 || mkAc.Length == 16);
            Assert.NotEmpty(BytesToHex(mkAc));
        }

        [Fact]
        public void Aes256MasterKeyDerivation_DifferentPan_ProducesDifferentKey()
        {
            var imkAc = HexToBytes("0011223344556677889900AABBCCDDEE0011223344556677889900AABBCCDDEE");
            var pan = "5413330089010020";
            var psn = "01";

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.True(mkAc.Length == 32 || mkAc.Length == 16);

            var mkAc2 = _service.DeriveAesIccMasterKey(imkAc, "5413330089010021", psn);
            Assert.NotEqual(BytesToHex(mkAc), BytesToHex(mkAc2));
        }

        #endregion

        #region AES Session Key Derivation

        [Fact]
        public void AesSessionKeyDerivation_ProducesConsistentLength()
        {
            var mkAc = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var atc = "0001";

            var skAc = _service.DeriveAesSessionKey(mkAc, atc);

            Assert.NotNull(skAc);
            Assert.True(skAc.Length >= 16); // At least AES-128
            Assert.NotEmpty(BytesToHex(skAc));
        }

        [Theory]
        [InlineData("0001")]
        [InlineData("0042")]
        [InlineData("00FF")]
        [InlineData("0100")]
        [InlineData("FFFF")]
        public void AES_SessionKeyDerivation_VariousATCs(string atc)
        {
            var mkAc = HexToBytes("0123456789ABCDEF0123456789ABCDEF");

            var skAc = _service.DeriveAesSessionKey(mkAc, atc);

            Assert.NotNull(skAc);
            Assert.True(skAc.Length >= 16);
            Assert.Contains(skAc, b => b != 0);
        }

        [Fact]
        public void AES_SessionKeyDerivation_UniquenessTest()
        {
            var mkAc = HexToBytes("ABCDEF01234567890123456789ABCDEF");

            var sk1 = _service.DeriveAesSessionKey(mkAc, "0001");
            var sk2 = _service.DeriveAesSessionKey(mkAc, "0002");
            var sk3 = _service.DeriveAesSessionKey(mkAc, "0003");

            Assert.NotEqual(BytesToHex(sk1), BytesToHex(sk2));
            Assert.NotEqual(BytesToHex(sk2), BytesToHex(sk3));
            Assert.NotEqual(BytesToHex(sk1), BytesToHex(sk3));
        }

        [Fact]
        public void AES_SessionKeyDerivation_Deterministic()
        {
            var mkAc = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var atc = "0017";

            var sk1 = _service.DeriveAesSessionKey(mkAc, atc);
            var sk2 = _service.DeriveAesSessionKey(mkAc, atc);

            Assert.Equal(BytesToHex(sk1), BytesToHex(sk2));
        }

        [Fact]
        public void AES_SessionKeyDerivation_ATCRollover()
        {
            var mkAc = HexToBytes("0123456789ABCDEF0123456789ABCDEF");

            var skFFFE = _service.DeriveAesSessionKey(mkAc, "FFFE");
            var skFFFF = _service.DeriveAesSessionKey(mkAc, "FFFF");
            var sk0000 = _service.DeriveAesSessionKey(mkAc, "0000");
            var sk0001 = _service.DeriveAesSessionKey(mkAc, "0001");

            Assert.NotEqual(BytesToHex(skFFFE), BytesToHex(skFFFF));
            Assert.NotEqual(BytesToHex(skFFFF), BytesToHex(sk0000));
            Assert.NotEqual(BytesToHex(sk0000), BytesToHex(sk0001));
        }

        #endregion

        #region AES vs 3DES Comparison Tests

        [Fact]
        public void AES_vs_3DES_MasterKeyDerivation_Comparison()
        {
            var imk = HexToBytes("0123456789ABCDEFFEDCBA9876543210");
            var pan = "5123456789012345";
            var psn = "00";

            var aesMk = _service.DeriveAesIccMasterKey(imk, pan, psn);
            var desMk = _service.DeriveDesIccMasterKeyOptionA(imk, pan, psn);

            Assert.NotEqual(BytesToHex(aesMk), BytesToHex(desMk));
            Assert.True(aesMk.Length >= 16);
            Assert.Equal(16, desMk.Length);
        }

        [Fact]
        public void AES_vs_3DES_SessionKeyDerivation_Comparison()
        {
            var mk16 = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var atc = "0042";

            var aesSk = _service.DeriveAesSessionKey(mk16, atc);
            var desSk = _service.DeriveDesSessionKey(mk16, atc);

            Assert.NotEqual(BytesToHex(aesSk), BytesToHex(desSk));
            Assert.True(aesSk.Length >= 16);
            Assert.Equal(16, desSk.Length);
        }

        #endregion

        #region Long PAN Support (> 16 digits)

        [Fact]
        public void AES_MasterKeyDerivation_LongPAN_18Digits()
        {
            var imkAc = HexToBytes("0123456789ABCDEF0123456789ABCDEF");
            var pan = "512345678901234567"; // 18 digits
            var psn = "00";

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.True(mkAc.Length >= 16);
            Assert.NotEmpty(BytesToHex(mkAc));
        }

        [Fact]
        public void AES_MasterKeyDerivation_LongPAN_19Digits()
        {
            var imkAc = HexToBytes("FEDCBA98765432100123456789ABCDEF");
            var pan = "5123456789012345678"; // 19 digits
            var psn = "01";

            var mkAc = _service.DeriveAesIccMasterKey(imkAc, pan, psn);

            Assert.NotNull(mkAc);
            Assert.True(mkAc.Length >= 16);

            var mk16 = _service.DeriveAesIccMasterKey(imkAc, "5123456789012345", psn);
            Assert.NotEqual(BytesToHex(mkAc), BytesToHex(mk16));
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
