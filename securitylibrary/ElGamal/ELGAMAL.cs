using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            // throw new NotImplementedException();
            // Compute c1
            long c1 = 1;

            for (long i = 0; i < k; i++)
            {
                c1 = (c1 * alpha) % q;
            }

            // Compute c2
            long A = 1;

            for (long i = 0; i < k; i++)
            {
                A = (A * y) % q;
            }

            long c2 = (A * m) % q;

            return new List<long> { c1, c2 };
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();
            // Calculate M = C2 * C1^(-x) mod q
            int c1_inverse = 1;
            for (int i = 0; i < q - 2; i++)
            {
                c1_inverse = (c1_inverse * c1) % q;
            }

            int c1_power = 1;
            for (int i = 0; i < x; i++)
            {
                c1_power = (c1_power * c1_inverse) % q;
            }

            int m = (c2 * c1_power) % q;

            return m;
        }

    }
}