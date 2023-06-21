using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        private int[,] ImplementKeyMatrix(List<int> key, int x)
        {

            int[,] keyM = new int[x, x];

            int counter = 0;
            for (int i = 0; i < x; i++)
            {
                for (int j = 0; j < x; j++)
                {
                    keyM[i, j] = key[counter];
                    counter++;
                }
            }
            return keyM;
        }
        private int[,] ImplementTextMatrix(List<int> text, int x)
        {
            int y = text.Count / x;
            int[,] plainTextM = new int[x, y];

            int counter = 0;
            for (int i = 0; i < y; i++)//col
            {
                for (int j = 0; j < x; j++)//row
                {
                    plainTextM[j, i] = text[counter];
                    counter++;
                }
            }
            return plainTextM;
        }
        private int DeterminantofMatrix(int[,] key, int x)
        {
            int Determinant = 0;
            if (x == 2)
            {
                Determinant = (key[0, 0] * key[1, 1]) - (key[0, 1] * key[1, 0]);

                return Determinant;
            }
            else if (x == 3)
            {
                Determinant = +(key[0, 0] * (key[1, 1] * key[2, 2] - key[2, 1] * key[1, 2]))
                              - (key[0, 1] * (key[1, 0] * key[2, 2] - key[1, 2] * key[2, 0]))
                              + (key[0, 2] * (key[1, 0] * key[2, 1] - key[1, 1] * key[2, 0]));

                return Determinant;
            }

            return Determinant;
        }
        private void Inverse(ref int[,] key, int m)
        {
            int determinant = 0;
            if (m == 2)
            {
                determinant = DeterminantofMatrix(key, m);
                while (determinant < 0)
                    determinant += 26;

                int temp = key[0, 0];
                key[0, 0] = key[1, 1];
                key[1, 1] = temp;
                key[0, 1] *= -1;
                key[1, 0] *= -1;

                int b = 0;
                for (int i = 1; i < 26; i++)
                {
                    if (((i * determinant) % 26) == 1)
                    {
                        b = i;
                        break;
                    }
                }

                if (b == 0)
                    throw new SystemException();

                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        while (key[i, j] < 0)
                            key[i, j] += 26;

                        key[i, j] *= b;
                        key[i, j] %= 26;
                    }
                }
            }
            else if (m == 3)
            {
                determinant = DeterminantofMatrix(key, m);

                while (determinant < 0)
                    determinant += 26;

                int b = 0;
                for (int i = 1; i < 26; i++)
                {
                    if (((i * determinant) % 26) == 1)
                    {
                        b = i;
                        break;
                    }
                }

                int[,] result = new int[m, m];
                result[0, 0] = ((key[1, 1] * key[2, 2] - key[2, 1] * key[1, 2]) * b);
                result[0, 1] = (-(key[1, 0] * key[2, 2] - key[1, 2] * key[2, 0]) * b);
                result[0, 2] = ((key[1, 0] * key[2, 1] - key[2, 0] * key[1, 1]) * b);

                result[1, 0] = (-(key[0, 1] * key[2, 2] - key[0, 2] * key[2, 1]) * b);
                result[1, 1] = ((key[0, 0] * key[2, 2] - key[0, 2] * key[2, 0]) * b);
                result[1, 2] = (-(key[0, 0] * key[2, 1] - key[2, 0] * key[0, 1]) * b);

                result[2, 0] = ((key[0, 1] * key[1, 2] - key[0, 2] * key[1, 1]) * b);
                result[2, 1] = (-(key[0, 0] * key[1, 2] - key[1, 0] * key[0, 2]) * b);
                result[2, 2] = ((key[0, 0] * key[1, 1] - key[1, 0] * key[0, 1]) * b);

                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        while (result[j, i] < 0)
                            result[j, i] += 26;
                    }
                }

                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        key[i, j] = result[j, i] % 26;
                    }
                }
            }
        }

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            List<int> key = new List<int>() { i, j, k, l };
                            List<int> cipher = Encrypt(plainText, key);
                            if (cipher.SequenceEqual(cipherText))
                            {
                                return key;
                            }
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            int m = (int)Math.Sqrt(key.Count);
            int[,] keyMatrix = ImplementKeyMatrix(key, m);
            int[,] cipherTextMatrix = ImplementTextMatrix(cipherText, m);

            int n = cipherText.Count / m;

            Inverse(ref keyMatrix, m);

            int[,] multMatrix = new int[m, n];

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    for (int k = 0; k < m; k++)
                    {
                        multMatrix[i, j] += keyMatrix[i, k] * cipherTextMatrix[k, j];
                    }
                }
            }

            List<int> plainText = new List<int> { };
            for (int i = 0; i < n; i++)//col
            {
                for (int j = 0; j < m; j++)//row
                {
                    plainText.Add(multMatrix[j, i] % 26);
                }
            }

            return plainText;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            int m = (int)Math.Sqrt(key.Count);
            int[,] keyMatrix = ImplementKeyMatrix(key, m);
            int[,] plainTextMatrix = ImplementTextMatrix(plainText, m);

            int n = plainText.Count / m;
            int[,] multMatrix = new int[m, n];

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    for (int k = 0; k < m; k++)
                    {
                        multMatrix[i, j] += keyMatrix[i, k] * plainTextMatrix[k, j];
                    }
                }
            }

            List<int> cipherText = new List<int> { };
            for (int i = 0; i < n; i++)//col
            {
                for (int j = 0; j < m; j++)//row
                {
                    cipherText.Add(multMatrix[j, i] % 26);
                }
            }

            return cipherText;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();
            int[,] plainTextMatrix = new int[3, 3];
            int[,] cipherTextMatrix = new int[3, 3];

            plainTextMatrix = ImplementTextMatrix(plain3, 3);
            cipherTextMatrix = ImplementTextMatrix(cipher3, 3);

            Inverse(ref plainTextMatrix, 3);

            int[,] keyMatrix = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int c = 0; c < 3; c++)
                {
                    for (int k = 0; k < 3; k++)
                    {
                        keyMatrix[i, c] += cipherTextMatrix[i, k] * plainTextMatrix[k, c];
                    }
                }

            }
            List<int> key = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    key.Add(keyMatrix[i, j] % 26);
                }
            }
            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
