using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int x = baseN;
            int y = number;
            int a1 = 1;
            int a2 = 0;
            int b1 = 0;
            int b2 = 1;
            int Q = 0;
            int restQ = 0;

            while (true)
            {
                Q = x / y;
                restQ = x % y;
                x = y;
                y = restQ;

                int last_a1 = a1;
                int last_a2 = a2;
                a1 = b1;
                a2 = b2;
                b1 = last_a1 - Q * a1;
                b2 = last_a2 - Q * a2;

                if (y == 0)
                {
                    return -1;        // Numbers cannot be resolved.
                }
                else if (y == 1)
                {

                    //Multiplicative Inverse       b2 mod First_X 
                    int Multiplicative_Inverse = b2 % baseN;
                    if (Multiplicative_Inverse < 0)
                    {
                        Multiplicative_Inverse += baseN; // Make sure result is positive.
                    }
                    return Multiplicative_Inverse;
                }
            }
        }
    }
}