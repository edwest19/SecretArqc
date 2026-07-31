// Copyright (c) 2026 edwest19
// This file was generated using Microsoft Copilot.
// Utility: Concatenates multiple byte arrays, used heavily in EMV data construction.

namespace SecretArqc.Core.Primitives
{
    /// <summary>
    /// Provides efficient concatenation of multiple byte arrays.
    /// Used in ARQC/ARPC data building, DOL construction, and key derivation.
    /// </summary>
    public static class ConcatUtils
    {
        public static byte[] Concat(params byte[][] arrays)
        {
            if (arrays == null)
                throw new ArgumentNullException(nameof(arrays));

            int totalLength = 0;
            foreach (var arr in arrays)
                if (arr != null)
                    totalLength += arr.Length;

            var result = new byte[totalLength];
            int offset = 0;

            foreach (var arr in arrays)
            {
                if (arr == null) continue;

                Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }

            return result;
        }
    }
}
