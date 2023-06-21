using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //q is prime
            //alpha is generator
            //xa and xb are private keys

            ////////////////////////////////////////
            // throw new NotImplementedException();
            ////////////////////////////////////////


            if (q <= 1 || alpha <= 1 || alpha >= q || xa <= 0 || xa >= q || xb <= 0 || xb >= q)
            {
                throw new ArgumentException("Invalid input values");
            }
            //calculate public keys
            int ya = CalculatePowerModulo(alpha, xa, q);
            int yb = CalculatePowerModulo(alpha, xb, q);
            //calculate secret keys
            int ka = CalculatePowerModulo(yb, xa, q);
            int kb = CalculatePowerModulo(ya, xb, q);

            if (ka != kb)
            {
                throw new Exception("Error: Keys do not match!");
            }
            List<int> keys = new List<int> { };
            keys.Add(ka);
            keys.Add(kb);
            return keys;
        }



        public int CalculatePowerModulo(int basenum, int exponent, int modulus)
        {
            //implemnt this equation
            //result= basenumber^exponent % modules
            int res = 1;
            for (int i = 0; i < exponent; i++)
            {
                res = (res * basenum) % modulus;
            }
            return res;
        }

    }
}