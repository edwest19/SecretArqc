// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Utility: Provides EMV PAN decimalisation used in 3DES Option A key derivation.

using System;
using System.Text;

namespace SecretArqc.Core.Primitives
{
    /// <summary>
    /// Provides EMV decimalisation utilities for PAN processing.
    /// Used in EMV 3DES Option A master key derivation.
    /// </summary>
    public static class DecimalisationUtils
    {
        /// <summary>
        /// Converts a PAN string into a decimalised numeric-only string.
        /// Non-numeric characters are mapped using the EMV decimalisation table.
        /// </summary>
        public static string Decimalise(string pan)
        {
            if (pan == null)
                throw new ArgumentNullException(nameof(pan));

            var sb = new StringBuilder(pan.Length);

            foreach (char c in pan)
            {
                if (char.IsDigit(c))
                {
                    sb.Append(c);
                }
                else
                {
                    // EMV decimalisation table: A-F → 0-5
                    // (This is the standard EMV mapping for hex PAN characters)
                    int mapped = c switch
                    {
                        'A' or 'a' => 0,
                        'B' or 'b' => 1,
                        'C' or 'c' => 2,
                        'D' or 'd' => 3,
                        'E' or 'e' => 4,
                        'F' or 'f' => 5,
                        _ => throw new ArgumentException($"Invalid PAN character: {c}")
                    };

                    sb.Append(mapped);
                }
            }

            return sb.ToString();
        }
    }
}
