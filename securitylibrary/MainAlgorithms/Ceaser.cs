using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {

            // throw new NotImplementedException();
            plainText = plainText.ToLower();
            char[] CipherText = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                CipherText[i] = Convert.ToChar(((int)plainText.ToCharArray()[i] + key - 97) % 26 + 97);
            }
            return new string(CipherText);
        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            char[] plainText = new char[cipherText.Length];
            for (int i = 0; i < cipherText.Length; i++)
            {
                int ascii = (int)cipherText.ToCharArray()[i] - key - 97;

                if (ascii < 0)
                {
                    plainText[i] = Convert.ToChar((ascii + 26) + 97);
                }
                else
                {
                    plainText[i] = Convert.ToChar(((ascii) % 26) + 97);
                }
            }
            return new string(plainText);
        }

        public int Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int plainAsci = (int)plainText[0];
            int cipherAci = (int)cipherText[0];
            int Result = cipherAci - plainAsci;
            if (Result < 0)
                return 26 + Result;
            return Result;
        }
    }
}