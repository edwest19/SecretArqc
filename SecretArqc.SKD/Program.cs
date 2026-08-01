// Copyright (c) 2026 edwest19
// All rights reserved.
// Ported from SecretEmv.SKD.

using SecretArqc.Core.Emv.SessionKeyDerivation;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: SecretArqc.SKD <mkac_hex> <diversification_hex>");
            Console.WriteLine("  mkac_hex: ICC Master Key in hex");
            Console.WriteLine("  diversification_hex: ATC (or other diversification data) in hex");
            Console.WriteLine();
            Console.WriteLine("Example:");
            Console.WriteLine("  SecretArqc.SKD 08DF3425322020A720EFF2C1343852E63D 3456");
            return;
        }

        string mkacHex = args[0];
        string diversificationHex = args[1];

        byte[] mkac = Convert.FromHexString(mkacHex);

        var deriver = new DesSessionKeyDeriver();
        byte[] skac = deriver.Derive(mkac, diversificationHex);

        Console.WriteLine(Convert.ToHexString(skac));
    }
}
