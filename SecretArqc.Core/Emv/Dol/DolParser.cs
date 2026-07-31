// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// EMV Engine: Parses EMV Data Object Lists (DOL) and builds corresponding data blocks.

using System;
using System.Collections.Generic;
using SecretArqc.Core.Primitives;

namespace SecretArqc.Core.Emv.Dol
{
    /// <summary>
    /// Provides full EMV DOL parsing and data block construction.
    /// 
    /// Responsibilities:
    /// - Parse a DOL (tag + length sequence) from raw bytes.
    /// - Represent each DOL entry as (Tag, Length).
    /// - Build the DOL data block from a tag→value dictionary.
    /// 
    /// Used for:
    /// - CDOL1/CDOL2
    /// - TDOL
    /// - DDOL
    /// - PDOL
    /// </summary>
    public class DolParser
    {
        /// <summary>
        /// Represents a single DOL entry (Tag + Length).
        /// </summary>
        public sealed class DolEntry
        {
            public string Tag { get; }
            public int Length { get; }

            public DolEntry(string tag, int length)
            {
                Tag = tag ?? throw new ArgumentNullException(nameof(tag));
                Length = length;
            }
        }

        /// <summary>
        /// Parses a DOL from raw bytes into a list of DolEntry.
        /// </summary>
        public IList<DolEntry> Parse(byte[] dolBytes)
        {
            if (dolBytes == null)
                throw new ArgumentNullException(nameof(dolBytes));

            var entries = new List<DolEntry>();
            int offset = 0;

            while (offset < dolBytes.Length)
            {
                // Parse tag (1–3 bytes, EMV-style)
                string tag = ParseTag(dolBytes, ref offset);

                if (offset >= dolBytes.Length)
                    throw new ArgumentException("Invalid DOL: missing length after tag.");

                // Length is one byte
                int length = dolBytes[offset++];
                entries.Add(new DolEntry(tag, length));
            }

            return entries;
        }

        /// <summary>
        /// Builds the DOL data block from parsed entries and a tag→value map.
        /// Values are truncated or padded with 0x00 to match the DOL length.
        /// </summary>
        public byte[] BuildDataBlock(IList<DolEntry> entries, IDictionary<string, byte[]> tagValues)
        {
            if (entries == null)
                throw new ArgumentNullException(nameof(entries));

            if (tagValues == null)
                throw new ArgumentNullException(nameof(tagValues));

            var parts = new List<byte[]>();

            foreach (var entry in entries)
            {
                if (!tagValues.TryGetValue(entry.Tag, out var value))
                    value = Array.Empty<byte>();

                byte[] adjusted = AdjustLength(value, entry.Length);
                parts.Add(adjusted);
            }

            return ConcatUtils.Concat(parts.ToArray());
        }

        /// <summary>
        /// Parses an EMV tag (1–3 bytes) starting at offset and advances offset.
        /// </summary>
        private string ParseTag(byte[] data, ref int offset)
        {
            if (offset >= data.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));

            var tagBytes = new List<byte>();

            // First byte
            byte first = data[offset++];
            tagBytes.Add(first);

            // If bit 5 of first byte is 1, tag is multi-byte
            if ((first & 0x1F) == 0x1F)
            {
                // Subsequent bytes: bit 8 = 1 means more bytes follow
                while (offset < data.Length)
                {
                    byte next = data[offset++];
                    tagBytes.Add(next);
                    if ((next & 0x80) == 0)
                        break;
                }
            }

            return HexUtils.ToHex(tagBytes.ToArray());
        }

        /// <summary>
        /// Truncates or pads a value to the required length with 0x00.
        /// </summary>
        private byte[] AdjustLength(byte[] value, int length)
        {
            var result = new byte[length];

            if (value != null && value.Length > 0)
            {
                int copyLen = Math.Min(value.Length, length);
                Buffer.BlockCopy(value, 0, result, 0, copyLen);
            }

            // Remaining bytes stay 0x00
            return result;
        }
    }
}
