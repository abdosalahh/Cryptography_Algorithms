using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.Trim().ToLower();
            plainText = plainText.Trim().ToLower();
            string AlphaPitic = "abcdefghijklmnopqrstuvwxyz";
            char[,] taple = MakeTaple();
            string key = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                char[] cloumn = Enumerable.Range(0, taple.GetLength(0)).Select(x => taple[AlphaPitic.IndexOf(plainText[i]), x]).ToArray();
                key += AlphaPitic[Array.IndexOf(cloumn, cipherText[i])];
            }
            string normalKey = key.Substring(0, key.Length - 1);
            while (normalKey != "")
            {
                if (cipherText == Encrypt(plainText, normalKey))
                {
                    key = normalKey;
                }
                normalKey = normalKey.Substring(0, normalKey.Length - 1);
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.Trim().ToLower();
            key = key.ToLower().Trim();
            string AlphaPitic = "abcdefghijklmnopqrstuvwxyz";
            char[,] taple = MakeTaple();
            string plainText = "";
            for (int i = 0; i < key.Length; i++)
            {
                char[] row = Enumerable.Range(0, taple.GetLength(1)).Select(x => taple[AlphaPitic.IndexOf(key[i]), x]).ToArray();
                plainText += AlphaPitic[Array.IndexOf(row, cipherText[i])];
                if (key.Length < cipherText.Length)
                {
                    key += plainText[plainText.Length - 1];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.Trim().ToLower();
            key = key.ToLower().Trim();
            string AlphaPitic = "abcdefghijklmnopqrstuvwxyz";
            char[,] taple = MakeTaple();
            while (key.Length < plainText.Length)
            {
                key = key + plainText.Substring(0, plainText.Length - key.Length);
            }
            string cipher = "";
            for (int i = 0; i < key.Length; i++)
            {
                cipher += taple[AlphaPitic.IndexOf(key[i]), AlphaPitic.IndexOf(plainText[i])];
            }
            return cipher;
        }

        public char[,] MakeTaple()
        {
            string AlphaPitic = "abcdefghijklmnopqrstuvwxyz";
            char[,] VigenTable = new char[26, 26];
            int charIter = 0;
            for (int i = 0; i < 26; i++)
            {
                charIter = i;
                for (int j = 0; j < 26; j++)
                {
                    if (charIter == AlphaPitic.Length)
                    {
                        charIter = 0;
                    }
                    VigenTable[i, j] = AlphaPitic[charIter++];
                }
            }
            return VigenTable;
        }
    }
}
