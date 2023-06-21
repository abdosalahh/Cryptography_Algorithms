using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            return (int)BigInteger.ModPow(M, e , (p * q));
        }
        public int Decrypt(int p, int q, int C, int e)
        {
            double d = modInverse(e, ((p - 1) * (q - 1)));
            return (int)BigInteger.ModPow(C, (int)d ,(p * q));
        }
        public static int modInverse(int A, int M)
        {

            for (int X = 1; X < M; X++)
                if (((A % M) * (X % M)) % M == 1)
                    return X;
            return 1;
        }
    }
}
