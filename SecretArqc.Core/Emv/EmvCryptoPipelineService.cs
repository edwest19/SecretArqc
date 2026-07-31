// Copyright (c) 2026 edwest19
// All rights reserved.
// This file was generated using Microsoft Copilot.

// EMV Service: Orchestrates full EMV crypto pipeline (master key derivation, session keys, ARQC, ARPC, DOL).

using SecretArqc.Core.Crypto;
using SecretArqc.Core.Emv.Arpc;
using SecretArqc.Core.Emv.Arqc;
using SecretArqc.Core.Emv.Dol;
using SecretArqc.Core.Emv.MasterKeyDerivation;
using SecretArqc.Core.Emv.SessionKeyDerivation;
using SecretArqc.Core.Primitives;
using SecretArqc.Core.Models;
using System;
using System.Collections.Generic;

namespace SecretArqc.Core.Emv
{
    /// <summary>
    /// High-level EMV crypto pipeline service.
    /// 
    /// Responsibilities:
    /// - Derive ICC master keys (DES/AES) from issuer keys + PAN/CSN.
    /// - Derive AC session keys (DES/AES) from ICC master keys + ATC.
    /// - Parse DOLs and build transaction data blocks.
    /// - Generate ARQC (3DES) and ARPC (Method 1/2).
    /// 
    /// This is the main façade that your UI or tools call.
    /// </summary>
    public class EmvCryptoPipelineService
    {
        private readonly DesMasterKeyDeriver _desMasterKeyDeriver = new DesMasterKeyDeriver();
        private readonly AesMasterKeyDeriver _aesMasterKeyDeriver = new AesMasterKeyDeriver();
        private readonly DesSessionKeyDeriver _desSessionKeyDeriver = new DesSessionKeyDeriver();
        private readonly AesSessionKeyDeriver _aesSessionKeyDeriver = new AesSessionKeyDeriver();
        private readonly DolParser _dolParser = new DolParser();
        private readonly ArqcEngine _arqcEngine = new ArqcEngine();
        private readonly ArpcEngine _arpcEngine = new ArpcEngine();

        public byte[] DeriveDesIccMasterKeyOptionA(byte[] issuerMasterKey, string pan, string csn)
            => _desMasterKeyDeriver.DeriveOptionA(issuerMasterKey, pan, csn);

        public byte[] DeriveDesIccMasterKeyOptionB(byte[] issuerMasterKey, string pan, string csn)
            => _desMasterKeyDeriver.DeriveOptionB(issuerMasterKey, pan, csn);

        public byte[] DeriveAesIccMasterKey(byte[] issuerMasterKey, string pan, string csn)
            => _aesMasterKeyDeriver.Derive(issuerMasterKey, pan, csn);

        public byte[] DeriveDesSessionKey(byte[] iccMasterKey, string atcHex)
            => _desSessionKeyDeriver.Derive(iccMasterKey, atcHex);

        public byte[] DeriveAesSessionKey(byte[] iccMasterKey, string atcHex)
            => _aesSessionKeyDeriver.Derive(iccMasterKey, atcHex);

        public byte[] BuildDolDataBlock(byte[] dolBytes, IDictionary<string, byte[]> tagValues)
        {
            var entries = _dolParser.Parse(dolBytes);
            return _dolParser.BuildDataBlock(entries, tagValues);
        }

        public byte[] GenerateArqc(
            byte[] issuerMasterKey,
            string pan,
            string csn,
            string atcHex,
            string unHex,
            byte[] dolBytes,
            IDictionary<string, byte[]> tagValues)
        {
            if (issuerMasterKey == null) throw new ArgumentNullException(nameof(issuerMasterKey));
            if (pan == null || csn == null) throw new ArgumentNullException();

            byte[] iccMasterKey = _desMasterKeyDeriver.DeriveOptionA(issuerMasterKey, pan, csn);
            byte[] skAc = _desSessionKeyDeriver.Derive(iccMasterKey, atcHex);

            var entries = _dolParser.Parse(dolBytes);
            byte[] transactionData = _dolParser.BuildDataBlock(entries, tagValues);

            return _arqcEngine.GenerateArqc(iccMasterKey, atcHex, unHex, transactionData);
        }

        public byte[] GenerateArpcMethod1(byte[] sessionKey, byte[] arqc, string arcHex)
            => _arpcEngine.GenerateMethod1(arqc, arcHex, sessionKey);

        public byte[] GenerateArpcMethod2(byte[] sessionKey, byte[] arqc, string arcHex)
            => _arpcEngine.GenerateMethod2(arqc, arcHex, sessionKey);

        public ArpcResult GenerateArpc(ArpcInput input)
        {
            var engine = new ArpcEngine();
            return engine.GenerateArpc(
                input.Arqc,
                input.Arc,
                input.SessionKeyAc
            );
        }

        public ArqcResult GenerateArqc(
    string sessionKeyHex,
    byte[] dolBytes,
    byte[] tagValuesBytes
)
        {
            var engine = new ArqcEngine();

            return engine.GenerateArqc(
                sessionKeyHex,
                dolBytes,
                tagValuesBytes
            );
        }

    }
}
