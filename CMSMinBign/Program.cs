using System;
using System.Collections.Generic;
using System.IO;

namespace CMSMinBign
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var arguments = ParseArguments(args);
            if (arguments.Count == 0 || arguments.ContainsKey("--help"))
            {
                PrintHelp();
                return; // Exit the application
            }
            
            if (arguments.ContainsKey("--certs"))
            {
                Console.WriteLine("Certs list:");
                List<ShortCertificate> certs = App.getCerts();
                foreach (ShortCertificate cert in certs)
                {
                    Console.WriteLine(cert.Index.ToString() + ". " + cert.Name);
                }
                return;
            }

            if (arguments.TryGetValue("--index", out string outputValue))
            {
                bool parsed = int.TryParse(outputValue, out int index);
                if(!parsed) 
                {
                    Console.WriteLine("Incorrect index value");
                    return;
                }

                String pin = arguments.GetValueOrDefault("--password", string.Empty);

                if (arguments.TryGetValue("--input", out string file))
                {
                    bool exists = File.Exists(file);
                    if(!exists)
                    {
                        Console.WriteLine("File not found");
                        return;
                    }

                    String outFile = arguments.GetValueOrDefault("--output", file + ".bin");
                    byte[] fileData = File.ReadAllBytes(file);
                    byte[] sign = App.Sign(index, fileData, pin);

                    if(arguments.ContainsKey("--base64"))
                    {
                        String result = Convert.ToBase64String(sign, 0, sign.Length);
                        File.WriteAllText(outFile, result);
                    }
                    else
                    {
                        File.WriteAllBytes(outFile, sign);
                    }

                    
                }    
            }
        }

        static Dictionary<string, string> ParseArguments(string[] args)
        {
            var arguments = new Dictionary<string, string>();

            foreach (var arg in args)
            {
                string[] parts = arg.Split('=');
                if (parts.Length == 2)
                {
                    arguments[parts[0]] = parts[1];
                }
                else
                {
                    arguments[arg] = null;
                }
            }

            return arguments;
        }

        static void PrintHelp()
        {
            Console.WriteLine("Help:");
            Console.WriteLine("------");
            Console.WriteLine("Usage: CMSMinBign.exe [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --help                 Display this help message");
            Console.WriteLine("  --certs                Display certs list");
            Console.WriteLine("  --index=<int>          Index of cert");
            Console.WriteLine("  --input=<file>         Path to signed file");
            Console.WriteLine("  --output=<file>        Specify output file");
            Console.WriteLine("  --password=<string>    Container password");
            Console.WriteLine("  --base64               Out sign as base64");
        }
    }
}
