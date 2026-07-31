// Copyright (c) 2026 edwest19
// All rights reserved.
// This file was generated using Microsoft Copilot.
using System;
using System.Collections.Generic;
using System.Text;

namespace SecretArqc.Core.Models
{
    public class ArqcResult
    {
        /// <summary>
        /// The generated ARQC (Application Request Cryptogram), 8 bytes hex.
        /// Example: "5A3F9C12A0B4D8E1".
        /// </summary>
        public string Arqc { get; set; } = string.Empty;

        /// <summary>
        /// The full MAC input data used to compute the ARQC.
        /// This is the CDOL1 data + ATC + UN, already concatenated.
        /// Useful for debugging and display.
        /// </summary>
        public string MacInputData { get; set; } = string.Empty;

        /// <summary>
        /// The session key SK_AC used to compute the ARQC.
        /// Included for transparency and debugging.
        /// </summary>
        public string SessionKeyAc { get; set; } = string.Empty;
    }
}
