// Copyright (c) 2026 edwest19
// All rights reserved.
// This file was generated using Microsoft Copilot.

using System;
using System.Collections.Generic;
using System.Text;

namespace SecretArqc.Core.Models
{
    public class SessionKeyInput
    {
        /// <summary>
        /// The Card Master Key for Application Cryptograms (MK-AC), 16 bytes hex.
        /// Example: "0123456789ABCDEFFEDCBA9876543210".
        /// </summary>
        public string MkAc { get; set; } = string.Empty;

        /// <summary>
        /// The Application Transaction Counter (ATC), 2 bytes hex.
        /// Example: "0023".
        /// </summary>
        public string Atc { get; set; } = string.Empty;
    }
}