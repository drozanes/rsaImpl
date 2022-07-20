using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace RsaImplementation
{
    class Program
    {
        static void Main(string[] args)
        {
            RSACore rsaCore = new RSACore();
            BigInteger n;
            int k = 5;
            //bool b = rsaCore.IsPrime(n, k);
            //Console.WriteLine("number " + n + " is " + b + ". Success=" + (b == true));


            //n = 101;
            //b = rsaCore.IsPrime(n, k);
            //Console.WriteLine("number " + n + " is " + b + ". Success=" + (b == true));

            //n = 17;
            //b = rsaCore.IsPrime(n, k);
            //Console.WriteLine("number " + n + " is " + b + ". Success=" + (b == true));

            //n = 19;
            //b = rsaCore.IsPrime(n, k);
            //Console.WriteLine("number " + n + " is " + b + ". Success=" + (b == true));

            //n = 223;
            //b = rsaCore.IsPrime(n, k);
            //Console.WriteLine("number " + n + " is " + b + ". Success=" + (b == true));


            Console.WriteLine("Welcome to RSA program");
            int intInput = 0;
            RSAKey key = null;
            while (intInput != 4)
            {

                Console.WriteLine("1 - Create new key");
                Console.WriteLine("2 - Encrypt text");
                Console.WriteLine("3 - Decrypt text");
                Console.WriteLine("4 - Exit");
                Console.WriteLine("5 - Check primarility");
                Console.WriteLine("6 - Use exists key");
                string input = Console.ReadLine();
                
                try
                {
                    if (int.TryParse(input, out intInput))
                    {
                        switch (intInput)
                        {
                            case 1:
                                key = rsaCore.GenerateKey();
                                break;
                            case 2: // encrypt
                                if (key == null)
                                {
                                    Console.WriteLine("Need to generate key before encrypt");
                                }
                                Console.WriteLine("write plaintext to encrypt");
                                BigInteger p = BigInteger.Parse( Console.ReadLine());
                                BigInteger c = rsaCore.Encrypt(p, key.publicKey);
                                Console.WriteLine("Chipertext:" + c);
                                break;
                            case 3: //decrypt
                                if (key == null)
                                {
                                    Console.WriteLine("Need to generate key before decrypt");
                                }
                                Console.WriteLine("write chipertext to decrypt");
                                c = BigInteger.Parse(Console.ReadLine());
                                p = rsaCore.Decrypt(c, key.privateKey);
                                Console.WriteLine("Plaintext:" + p);
                                break;
                            case 5:
                                Console.WriteLine("Enter number to check primarility");
                                BigInteger num = BigInteger.Parse(Console.ReadLine());
                                Console.WriteLine("Enter k for algorithm");
                                k = Convert.ToInt32(Console.ReadLine());
                                Console.WriteLine("number " + num + " is " + rsaCore.IsPrime(num));
                                break;
                            case 6:
                                Console.WriteLine("Enter number for e");
                                long e = long.Parse(Console.ReadLine());
                                Console.WriteLine("Enter number for d");
                                BigInteger d = BigInteger.Parse(Console.ReadLine());
                                Console.WriteLine("Enter number for n");
                                n = BigInteger.Parse(Console.ReadLine());
                                key = new RSAKey()
                                {
                                    privateKey = new RSAPrivateKey { d = d, n = n },
                                    publicKey = new RSAPublicKey { e = e, n = n }
                                };

                                break;
                        }
                    }
                }
                catch (Exception eX)
                {
                    Console.WriteLine("exception:" + eX);
                }
            }
        }
    }
}
