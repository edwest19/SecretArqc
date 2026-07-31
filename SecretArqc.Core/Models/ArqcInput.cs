// Copyright (c) 2026 edwest19
// All rights reserved.
// This file was generated using Microsoft Copilot.

using System;
using System.Collections.Generic;
using System.Text;

namespace SecretArqc.Core.Models
{
    public class ArqcInput
    {
        /// <summary>
        /// The session key SK_AC derived from IMK-AC.
        /// </summary>
        public string SessionKeyAc { get; set; } = string.Empty;

        /// <summary>
        /// The unpredictable number (UN), 4 bytes hex.
        /// Example: "6F3A2C19".
        /// </summary>
        public string UnpredictableNumber { get; set; } = string.Empty;

        /// <summary>
        /// The Application Transaction Counter (ATC), 2 bytes hex.
        /// Example: "0023".
        /// </summary>
        public string Atc { get; set; } = string.Empty;

        /// <summary>
        /// The card data input for ARQC generation (CDOL1 data),
        /// already formatted as a hex string.
        /// </summary>
        public string Cdol1Data { get; set; } = string.Empty;
    }
}
