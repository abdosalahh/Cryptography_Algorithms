using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            int rows = 0, col = 0;
            cipherText = cipherText.ToLower();

            for (int i = 2; i < 8; i++)
            {
                if (cipherText.Length % i == 0)
                {
                    col = i;
                }
            }

            rows = cipherText.Length / col;
            char[,] first = new char[rows, col];
            char[,] final = new char[rows, col];
            List<int> key = new List<int>(col);

            //to compare the plaintext and ciphertext
            int counter = 0;
            for (int i = 0; i < rows; i++)
            {
                int j = 0;
                while (j < col)

                {
                    if (counter < plainText.Length)
                    {
                        first[i, j] = plainText[counter];
                        counter++;
                    }
                    j++;
                }

            }
            counter = 0;
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    if (counter < cipherText.Length)
                    {
                        final[j, i] = cipherText[counter];
                        counter++;
                    }
                }
            }

            int count = 0;
            for (int i = 0; i < col; i++)
            {
                for (int k = 0; k < col; k++)
                {

                    int j = 0;
                    while (j < rows)
                    {
                        if (first[j, i] == final[j, k])
                        {
                            count++;
                        }
                        if (count == rows)
                        {
                            key.Add(k + 1);
                        }
                        j++;
                    }
                    count = 0;
                }
            }

            if (key.Count == 0)
            {
                for (int i = 0; i < col + 2; i++)
                {
                    key.Add(0);
                }
            }
            return key;

        }

        public string Decrypt(string cipherText, List<int> key)
        {

            cipherText = cipherText.ToUpper();
            int arr = cipherText.Length;
            if (arr % key.Count != 0)
            {
                arr = arr + key.Count;
            }
            int col = arr / key.Count;
            char[,] encrypt = new char[col, key.Count];
            int k = 0;
            int n = 0;
            for (int i = 0; i < key.Count; i++)
            {
                k = key.IndexOf(i + 1);
                for (int j = 0; j < col; j++)
                {
                    if (n < cipherText.Length)
                    {
                        encrypt[j, k] = cipherText[n];
                        n++;
                    }
                }
            }
            string word = "";
            for (int i = 0; i < col; i++)
            {
                int j = 0;
                while (j < key.Count)
                {
                    word = word + encrypt[i, j];
                    j++;
                }
            }
            return word.ToUpper();

        }

        public string Encrypt(string plainText, List<int> key)
        {
            int keyLength = key.Count;

            int paddingLength = (keyLength - plainText.Length % keyLength) % keyLength;
            string paddedPlainText = plainText.PadRight(plainText.Length + paddingLength, 'x');

            List<string> grid = new List<string>();
            for (int i = 0; i < paddedPlainText.Length; i += keyLength)
            {
                grid.Add(paddedPlainText.Substring(i, keyLength));
            }

            List<int> columnOrder = Enumerable.Range(0, keyLength).OrderBy(x => key[x]).ToList();

            StringBuilder encryptedMessage = new StringBuilder();
            foreach (int i in columnOrder)
            {
                foreach (string row in grid)
                {
                    if (i < row.Length)
                    {
                        encryptedMessage.Append(row[i]);
                    }
                }
            }


            return encryptedMessage.ToString();



        }
    }
}