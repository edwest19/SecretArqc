// Copyright (c) 2026 edwest19
// All rights reserved.
// This file was generated using Microsoft Copilot.

using System;
using System.Collections.Generic;
using System.Text;

namespace SecretArqc.Core.Models
{
    public class ArpcResult
    {
        /// <summary>
        /// The generated ARPC (Application Response Cryptogram), 8 bytes hex.
        /// Example: "1122334455667788".
        /// </summary>
        public string Arpc { get; set; } = string.Empty;

        /// <summary>
        /// The issuer authentication response code (ARC) used in ARPC generation.
        /// Example: "3030" for "00".
        /// </summary>
        public string Arc { get; set; } = string.Empty;

        /// <summary>
        /// The session key SK_AC used to compute the ARPC.
        /// Included for transparency and debugging.
        /// </summary>
        public string SessionKeyAc { get; set; } = string.Empty;

        /// <summary>
        /// The full MAC input data used to compute the ARPC.
        /// Useful for debugging and display.
        /// </summary>
        public string MacInputData { get; set; } = string.Empty;
    }
}

