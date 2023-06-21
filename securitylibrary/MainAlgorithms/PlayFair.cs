using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            string alphapitic = "abcdefghiklmnopqrstuvwxyz";
            char[,] matrix = new char[5, 5];
            key = new String((key.ToLower() + alphapitic).Distinct().ToArray());
            int index = 0;
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    matrix[i, j] = key[index];
                    index++;
                }
            }
            cipherText = cipherText.ToLower();
            string NwePlanText = cipherText;

            string plainText = "";
            for (int k = 0; k < NwePlanText.Length; k += 2)
            {
                string pos1 = getPosition(matrix, NwePlanText[k]);
                int pos1X = pos1[0] - '0';
                int pos1Y = pos1[1] - '0';
                string pos2 = getPosition(matrix, NwePlanText[k + 1]);
                int pos2X = pos2[0] - '0';
                int pos2Y = pos2[1] - '0';

                if (pos1X == pos2X)
                {
                    if (pos1Y == 0)
                    {
                        plainText += matrix[pos1X, 4];
                        plainText += matrix[pos2X, pos2Y - 1];
                    }
                    else if (pos2Y == 0)
                    {
                        plainText += matrix[pos1X, pos1Y - 1];
                        plainText += matrix[pos2X, 4];
                    }
                    else
                    {
                        plainText += matrix[pos1X, pos1Y - 1];
                        plainText += matrix[pos2X, pos2Y - 1];
                    }

                }
                else if (pos1Y == pos2Y)
                {
                    if (pos1X == 0)
                    {
                        plainText += matrix[4, pos1Y];
                        plainText += matrix[pos2X - 1, pos2Y];
                    }
                    else if (pos2X == 0)
                    {
                        plainText += matrix[pos1X - 1, pos1Y];
                        plainText += matrix[4, pos2Y];
                    }
                    else
                    {
                        plainText += matrix[pos1X - 1, pos1Y];
                        plainText += matrix[pos2X - 1, pos2Y];
                    }
                }
                else
                {
                    plainText += matrix[pos1X, pos2Y];
                    plainText += matrix[pos2X, pos1Y];
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                if (i != plainText.Length - 1)
                {
                    if (plainText[i] == 'x' && (plainText[i - 1] == plainText[i + 1]) && i % 2 != 0)
                    {
                        plainText = plainText.Substring(0, i) + " " + plainText.Substring(i + 1);
                    }
                }
                else
                {
                    if (plainText[i] == 'x')
                    {
                        plainText = plainText.Remove(i, 1);
                    }
                }
            }
            plainText = plainText.Replace(" ", "");
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string alphapitic = "abcdefghiklmnopqrstuvwxyz";
            char[,] matrix = new char[5, 5];
            key = new String((key.ToLower() + alphapitic).Distinct().ToArray());
            int index = 0;
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    matrix[i, j] = key[index];
                    index++;
                }
            }
            plainText = plainText.ToLower();
            string NwePlanText = plainText;

            for (int i = 0; i < NwePlanText.Length; i++)
            {
                if (i != NwePlanText.Length - 1)
                {
                    if (NwePlanText[i] == NwePlanText[i + 1] && i % 2 == 0)
                    {
                        NwePlanText = NwePlanText.Substring(0, i + 1) + "x" + NwePlanText.Substring(i + 1);
                    }
                }

            }

            if (NwePlanText.Length % 2 != 0)
            {
                NwePlanText += "x";
            }
            Console.WriteLine("plain text = " + NwePlanText);
            string ChipherText = "";
            for (int k = 0; k < NwePlanText.Length; k += 2)
            {
                string pos1 = getPosition(matrix, NwePlanText[k]);
                int pos1X = pos1[0] - '0';
                int pos1Y = pos1[1] - '0';
                string pos2 = getPosition(matrix, NwePlanText[k + 1]);
                int pos2X = pos2[0] - '0';
                int pos2Y = pos2[1] - '0';

                Console.WriteLine(pos1);
                Console.WriteLine(pos2);
                if (pos1X == pos2X)
                {
                    if (pos1Y == 4)
                    {
                        ChipherText += matrix[pos1X, 0];
                        ChipherText += matrix[pos2X, pos2Y + 1];
                    }
                    else if (pos2Y == 4)
                    {
                        ChipherText += matrix[pos1X, pos1Y + 1];
                        ChipherText += matrix[pos2X, 0];
                    }
                    else
                    {
                        ChipherText += matrix[pos1X, pos1Y + 1];
                        ChipherText += matrix[pos2X, pos2Y + 1];
                    }

                }
                else if (pos1Y == pos2Y)
                {
                    if (pos1X == 4)
                    {
                        ChipherText += matrix[0, pos1Y];
                        ChipherText += matrix[pos2X + 1, pos2Y];
                    }
                    else if (pos2X == 4)
                    {
                        ChipherText += matrix[pos1X + 1, pos1Y];
                        ChipherText += matrix[0, pos2Y];
                    }
                    else
                    {
                        ChipherText += matrix[pos1X + 1, pos1Y];
                        ChipherText += matrix[pos2X + 1, pos2Y];
                    }
                }
                else
                {
                    ChipherText += matrix[pos1X, pos2Y];
                    ChipherText += matrix[pos2X, pos1Y];
                }
            }
            return ChipherText;
        }
        public static string getPosition(char[,] matrix, char c)
        {
            string postion = "";
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(1); j++)
                {
                    if (c == 'j')
                    {
                        c = 'i';
                    }
                    if (matrix[i, j].Equals(c))
                    {
                        return postion + i + j;
                    }
                }
            }
            return postion;
        }
    }
}