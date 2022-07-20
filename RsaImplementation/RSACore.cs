using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RsaImplementation
{
    public class RSACore
    {
        private RandomNumberGenerator randomGenerator = RandomNumberGenerator.Create();
        public int k = 20;
        public long e = 65537;

        public RSAKey GenerateKey()
        {
            BigInteger p, q;
            GeneratePrimeNumber(out p);
            GeneratePrimeNumber(out q);
            Console.WriteLine(p);
            Console.WriteLine(q);
            BigInteger n = p * q;
            BigInteger gama = (q - 1) * (p - 1);
            BigInteger d = CalculateD(e, gama);
            RSAPublicKey publicKey = new RSAPublicKey { e = e, n = n };
            RSAPrivateKey privateKey = new RSAPrivateKey { d = d, n = n };

            return new RSAKey() { privateKey = privateKey, publicKey = publicKey };
        }

        public BigInteger Encrypt(BigInteger p, RSAPublicKey publicKey)
        {
            return EncryptDecryptInternal(p, publicKey.e, publicKey.n);
        }

        private BigInteger EncryptDecryptInternal(BigInteger data, BigInteger exponent, BigInteger modolus)
        {
            int blockSize = 16;
            byte[] plainBytes = data.ToByteArray();
            List<byte[]> chiperBytesList = new List<byte[]>();
            int numOfBlocks = plainBytes.Length % blockSize == 0 ? plainBytes.Length / blockSize : plainBytes.Length / blockSize + 1;
            int numOfResBytes = 0;
            for (int i = 0; i < numOfBlocks; i++)
            {
                BigInteger partP = new BigInteger(plainBytes.Skip(i * blockSize).Take(blockSize).ToArray());
                byte[] partC = BigInteger.ModPow(partP, exponent, modolus).ToByteArray();
                chiperBytesList.Add(partC);
                numOfResBytes += partC.Length;
            }

            byte[] chiperBytes = new byte[numOfResBytes];
            int offset = 0;
            foreach (byte[] bytes in chiperBytesList)
            {
                Buffer.BlockCopy(bytes, 0, chiperBytes, offset, bytes.Length);
                offset += bytes.Length;

            }

            BigInteger res = new BigInteger(chiperBytes);
            return res;

        }


        public BigInteger Decrypt(BigInteger c, RSAPrivateKey privateKey)
        {
            return EncryptDecryptInternal(c, privateKey.d, privateKey.n);
        }


        public bool IsPrime(BigInteger n)
        {
            if (n.IsEven)
            {
                return false;
            }

            int s = 0;
            BigInteger d = n - 1;

            while (d.IsEven)
            {
                d = d / 2;
                s++;
            }

            for (int i = 0; i < k; i++)
            {
                BigInteger a = RandomInRange(2, n - 2);
                BigInteger x = BigInteger.ModPow(a, d, n);
                if (x == 1 || x == n - 1)
                    continue;
                for (int j = 0; j < s; j++)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == n - 1)
                        continue;
                }
                return false;
            }

            return true;
        }

        private BigInteger CalculateD(long e, BigInteger gama)
        {
            BigInteger u = e, v = gama;
            BigInteger inv, u1, u3, v1, v3, t1, t3, q;
            BigInteger iter;
            /* Step X1. Initialise */
            u1 = 1;
            u3 = u;
            v1 = 0;
            v3 = v;
            /* Remember odd/even iterations */
            iter = 1;
            /* Step X2. Loop while v3 != 0 */
            while (v3 != 0)
            {
                /* Step X3. Divide and "Subtract" */
                q = u3 / v3;
                t3 = u3 % v3;
                t1 = u1 + q * v1;
                /* Swap */
                u1 = v1; v1 = t1; u3 = v3; v3 = t3;
                iter = -iter;
            }
            /* Make sure u3 = gcd(u,v) == 1 */
            if (u3 != 1)
                return 0;   /* Error: No inverse exists */
            /* Ensure a positive result */
            if (iter < 0)
                inv = v - u1;
            else
                inv = u1;
            return inv;
        }

        private void GeneratePrimeNumber(out BigInteger num)
        {
            num = 0;
            while (IsPrime(num) == false ||
                e >= (num - 1) ||
                BigInteger.GreatestCommonDivisor(num - 1, e) != 1)   //while choosing number, we verify that num-1 is coprime to e
            {
                num = RandomInRangeFromZeroToPositive(long.MaxValue);
            }
        }

        private BigInteger RandomInRange(BigInteger min, BigInteger max)
        {
            if (min > max)
            {
                var buff = min;
                min = max;
                max = buff;
            }

            // offset to set min = 0
            BigInteger offset = -min;
            min = 0;
            max += offset;

            var value = RandomInRangeFromZeroToPositive(max) - offset;
            return value;
        }

        private BigInteger RandomInRangeFromZeroToPositive(BigInteger max)
        {
            BigInteger value;
            var bytes = max.ToByteArray();

            // count how many bits of the most significant byte are 0
            // NOTE: sign bit is always 0 because `max` must always be positive
            byte zeroBitsMask = 0b00000000;

            var mostSignificantByte = bytes[bytes.Length - 1];

            // we try to set to 0 as many bits as there are in the most significant byte, starting from the left (most significant bits first)
            // NOTE: `i` starts from 7 because the sign bit is always 0
            for (var i = 7; i >= 0; i--)
            {
                // we keep iterating until we find the most significant non-0 bit
                if ((mostSignificantByte & (0b1 << i)) != 0)
                {
                    var zeroBits = 7 - i;
                    zeroBitsMask = (byte)(0b11111111 >> zeroBits);
                    break;
                }
            }

            do
            {
                randomGenerator.GetBytes(bytes);

                // set most significant bits to 0 (because `value > max` if any of these bits is 1)
                bytes[bytes.Length - 1] &= zeroBitsMask;

                value = new BigInteger(bytes);

                // `value > max` 50% of the times, in which case the fastest way to keep the distribution uniform is to try again
            } while (value > max);

            return value;
        }


    }
}
