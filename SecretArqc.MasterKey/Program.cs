// Copyright (c) 2026 edwest19
// All rights reserved.
// Ported from SecretEmv.MasterKey.

using SecretArqc.Core.Emv.MasterKeyDerivation;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.WriteLine("Usage: SecretArqc.MasterKey <option> <imk_hex> <pan> <psn>");
            Console.WriteLine("  option: A or B");
            Console.WriteLine("  imk_hex: Issuer Master Key in hex (32 characters)");
            Console.WriteLine("  pan: Primary Account Number (digits)");
            Console.WriteLine("  psn: PAN Sequence Number (digits)");
            Console.WriteLine();
            Console.WriteLine("Example (Option A):");
            Console.WriteLine("  SecretArqc.MasterKey A 9E15204313F7318ACB79B90BD986AD29 5413330089010000 01");
            Console.WriteLine();
            Console.WriteLine("Example (Option B, Long PAN):");
            Console.WriteLine("  SecretArqc.MasterKey B 9E15204313F7318ACB79B90BD986AD29 541333900000006165 00");
            return;
        }

        string option = args[0].ToUpper();
        string imkHex = args[1];
        string pan = args[2];
        string psn = args[3];

        byte[] imk = Convert.FromHexString(imkHex);
        var deriver = new DesMasterKeyDeriver();

        byte[] mkac;
        if (option == "A")
        {
            mkac = deriver.DeriveOptionA(imk, pan, psn);
            Console.WriteLine($"Option A - MKAC: {Convert.ToHexString(mkac)}");
        }
        else if (option == "B")
        {
            mkac = deriver.DeriveOptionB(imk, pan, psn);
            Console.WriteLine($"Option B - MKAC: {Convert.ToHexString(mkac)}");
        }
        else
        {
            Console.WriteLine($"Invalid option: {option}. Use A or B.");
            return;
        }
    }
}
