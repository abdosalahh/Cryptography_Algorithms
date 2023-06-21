using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int pltlength = plainText.Length;
            int[] key = new int[pltlength];
            int keylength = key.Length;
            for (int i = 0; i < pltlength; i++)
            {
                if (plainText[i] == cipherText[1])
                {
                    key[i] = i;
                }
            }
            for (int j = 0; j < keylength;j++)
            {
                string stringciphtxt = Encrypt(plainText, key[j]);
                stringciphtxt = stringciphtxt.ToLower();
                if (String.Equals(cipherText, stringciphtxt))
                {
                    return key[j];
                }
            }
            return -1;
        }
        public string Decrypt(string cipherText, int key)
        {
            String plainText = "";
            cipherText = cipherText.ToLower();
            double cplength = cipherText.Length;
            int pltlength = (int)Math.Ceiling(cplength / key);
            char[] matrix = cipherText.ToCharArray();
            for (int i = 0; i < pltlength; i++)
            {
                for (int j = i; j < cplength; j += pltlength)
                {
                    plainText += matrix[j];
                }
            }
            plainText = plainText.ToLower();
            return plainText;
        }
        public string Encrypt(string plainText, int key)
        {
            String cipherText = "";
            plainText = plainText.ToLower();
            int pltlength = plainText.Length;
            char[] matrix = plainText.ToCharArray();

            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < pltlength; j += key)
                {
                    cipherText += matrix[j];
                }
            }
            return cipherText;
        }
    }
}