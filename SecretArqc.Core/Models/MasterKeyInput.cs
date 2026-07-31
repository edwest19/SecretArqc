// Copyright (c) 2026 edwest19
// All rights reserved.
// This file was generated using Microsoft Copilot.
namespace SecretArqc.Core.Models
{
    public class MasterKeyInput
    {
        /// <summary>
        /// The Issuer Master Key for Application Cryptograms (IMK-AC), 16 bytes hex.
        /// Example: "0123456789ABCDEFFEDCBA9876543210".
        /// </summary>
        public string ImkAc { get; set; } = string.Empty;

        /// <summary>
        /// The Primary Account Number (PAN), digits only.
        /// Example: "4761739001010010".
        /// </summary>
        public string Pan { get; set; } = string.Empty;

        /// <summary>
        /// The PAN Sequence number Transaction Counter (PSN), 1 bytes hex.
        /// Example: "00".
        /// </summary>
        public string Psn { get; set; } = "00";         // PSN (2 digits, default 00)
    }
}
