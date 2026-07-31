// Copyright (c) 2026 edwest19
// All rights reserved.
// This file was generated using Microsoft Copilot.

using System;
using System.Collections.Generic;
using System.Text;

namespace SecretArqc.Core.Models
{
    public class ArpcInput
    {
        /// <summary>
        /// The ARQC generated in the previous step.
        /// </summary>
        public string Arqc { get; set; } = string.Empty;

        /// <summary>
        /// The issuer authentication response code (ARC), 2 bytes hex.
        /// Example: "3030" for "00".
        /// </summary>
        public string Arc { get; set; } = string.Empty;

        /// <summary>
        /// The session key SK_AC derived from IMK-AC.
        /// </summary>
        public string SessionKeyAc { get; set; } = string.Empty;
    }
}

