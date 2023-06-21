using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            String key = "";
            String alpha = "abcdefghijklmnopqrstuvwxyz";
            String nonCipher = "";
            int indexnonCipher = 0;
            for (int i = 0; i < alpha.Length; i++)
            {
                if (!cipherText.Contains(alpha[i]))
                {
                    nonCipher += alpha[i];
                }
            }
            for(int j=0; j < alpha.Length; j++)
            {
                bool flag = false;
                int indexCipher = 0;
                for (int k = 0; k < plainText.Length; k++)
                {
                    if (alpha[j] == plainText[k])
                    {
                        flag = true;
                        indexCipher = k;
                    }
                }
                if (flag)
                {
                    key += cipherText[indexCipher];
                }
                else
                {
                    key += nonCipher[indexnonCipher];
                    indexnonCipher++;
                }
            }
            key.ToLower();
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            String plainText = "";
            String alpha = "abcdefghijklmnopqrstuvwxyz";
            for(int i = 0 ; i < cipherText.Length ; i++)
            {
                for(int j = 0 ; j < key.Length ; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        plainText += alpha[j];
                    }
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            key = key.ToLower();
            String cipherText = "";
            String alpha = "abcdefghijklmnopqrstuvwxyz";
            for(int i = 0 ; i < plainText.Length ; i++)
            {
                for(int j = 0 ; j < alpha.Length ; j++)
                {
                    if (plainText[i] == alpha[j])
                    {
                        cipherText += key[j];
                    }
                }
            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
            String alphafreq = "etaoinsrhldcumfpgwybvkxjqz";
            String freqcipher = "";
            IDictionary<char, int> diccipherFreq = new Dictionary<char, int>();
            cipher = cipher.ToLower();
            IDictionary<char, char> dicalphafreq = new Dictionary<char, char>();
            for (int i = 0; i < cipher.Length; i++)
            {
                if (!diccipherFreq.ContainsKey(cipher[i]))
                    diccipherFreq.Add(cipher[i], 0);
                else
                    diccipherFreq[cipher[i]]++;
            }
            int conut = 0;
            var decendingCipherText = from begin in diccipherFreq orderby begin.Value descending select begin;
            foreach (var alpha in decendingCipherText)
            {
                dicalphafreq.Add(alpha.Key, alphafreq[conut]);
                conut++;
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                freqcipher += dicalphafreq[cipher[i]];
            }
            return freqcipher;
        }
    }
}