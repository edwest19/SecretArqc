// Copyright (c) 2026 edwest19
// Configuration model for saving/loading EMV ARQC/ARPC generator settings.

using System;

namespace SecretArqc.Core.Models
{
    /// <summary>
    /// Represents a saved configuration for EMV ARQC/ARPC generation.
    /// </summary>
    public class EmvConfiguration
    {
        public string ConfigName { get; set; } = "Default";
        public DateTime SavedAt { get; set; } = DateTime.Now;
        
        // Cipher Settings
        public bool Use3Des { get; set; } = true;
        public string DerivationMethod { get; set; } = "OptionA"; // OptionA, OptionB, Option3
        public int AesKeyLength { get; set; } = 128; // 128, 192, 256
        
        // Card Master Key
        public string ImkAc { get; set; } = string.Empty;
        public string Pan { get; set; } = string.Empty;
        public string Psn { get; set; } = string.Empty;
        public string CardMasterKey { get; set; } = string.Empty;
        
        // Session Key
        public string Atc { get; set; } = string.Empty;
        public string SessionKey { get; set; } = string.Empty;
        
        // ARQC/ARPC
        public string Dol { get; set; } = string.Empty;
        public string TagValues { get; set; } = string.Empty;
        public string Arc { get; set; } = string.Empty;  // Changed from "3030"
        public string Arqc { get; set; } = string.Empty;
        public string Arpc { get; set; } = string.Empty;
    }
}