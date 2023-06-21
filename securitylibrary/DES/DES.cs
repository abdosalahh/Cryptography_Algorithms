using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        int[,] PC_1 = new int[8, 7] {
                { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 } };

        int[,] PC_2 = new int[8, 6] {
                { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 } };

        int[,] sBox1 = new int[4, 16] {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };

        int[,] sBox2 = new int[4, 16] {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };

        int[,] sBox3 = new int[4, 16] {
                { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };

        int[,] sBox4 = new int[4, 16] {
                { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };

        int[,] sBox5 = new int[4, 16] {
                { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };

        int[,] sBox6 = new int[4, 16] {
                { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };

        int[,] sBox7 = new int[4, 16] {
                { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };

        int[,] sBox8 = new int[4, 16] {
                { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

        int[,] Permutation = new int[8, 4] {
                { 16, 7, 20, 21 },
                { 29, 12, 28, 17 },
                { 1, 15, 23, 26 },
                { 5, 18, 31, 10 },
                { 2, 8, 24, 14 },
                { 32, 27, 3, 9 },
                { 19, 13, 30, 6 },
                { 22, 11, 4, 25 } };

        int[,] ExpansionPermutation = new int[8, 6] {
                { 32, 1, 2, 3, 4, 5 },
                { 4, 5, 6, 7, 8, 9  },
                { 8, 9, 10, 11, 12, 13 },
                { 12, 13, 14, 15, 16, 17 },
                { 16, 17, 18, 19, 20, 21 },
                { 20, 21, 22, 23, 24, 25 },
                { 24, 25, 26, 27, 28, 29 },
                { 28, 29, 30, 31, 32, 1  } };

        int[,] IInitialPermutation = new int[8, 8] {
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1  },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 } };

        int[,] InitialPermutation_inverse = new int[8, 8] {
                { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25  } };
        public string Permutaion(int[,] table, string input, int numRows, int numColumns)
        {
            var output = new StringBuilder(numRows * numColumns);
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < numColumns; j++)
                {
                    int index = table[i, j] - 1;
                    if (index < 0 || index >= input.Length)
                    {
                        throw new ArgumentException("Invalid index in permutation table.");
                    }
                    output.Append(input[index]);
                }
            }
            return output.ToString();
        }
        public void CircularShiftLeft(List<string> a1, List<string> a2, string key2_28, string key1_28)
        {
            for (int i = 0; i < 16; i++)
            {
                string temp1 = key1_28.Substring(0, 1);
                key1_28 = key1_28.Remove(0, 1) + temp1;

                string temp2 = key2_28.Substring(0, 1);
                key2_28 = key2_28.Remove(0, 1) + temp2;

                if (i != 0 && i != 1 && i != 8 && i != 15)
                {
                    temp1 = key1_28.Substring(0, 1);
                    key1_28 = key1_28.Remove(0, 1) + temp1;
                    temp2 = key2_28.Substring(0, 1);
                    key2_28 = key2_28.Remove(0, 1) + temp2;
                }

                a1.Add(key1_28);
                a2.Add(key2_28);
            }
        }

        public List<string> Add_round_keys(List<string> keys)
        {
            List<string> roundKeys = new List<string>();
            foreach (string key in keys)
            {
                string roundKey = Permutaion(PC_2, key, 8, 6);
                roundKeys.Add(roundKey);
            }
            return roundKeys;
        }

        public string SBOX(List<string> separatedPlain)
        {
            StringBuilder res = new StringBuilder();

            for (int i = 0; i < separatedPlain.Count; i++)
            {
                string t = separatedPlain[i];
                string tmp1 = $"{t[0]}{t[5]}";
                string tmp2 = $"{t[1]}{t[2]}{t[3]}{t[4]}";

                int row = Convert.ToInt32(tmp1, 2);
                int col = Convert.ToInt32(tmp2, 2);

                int result = 0;
                switch (i)
                {
                    case 0:
                        result = sBox1[row, col];
                        break;
                    case 1:
                        result = sBox2[row, col];
                        break;
                    case 2:
                        result = sBox3[row, col];
                        break;
                    case 3:
                        result = sBox4[row, col];
                        break;
                    case 4:
                        result = sBox5[row, col];
                        break;
                    case 5:
                        result = sBox6[row, col];
                        break;
                    case 6:
                        result = sBox7[row, col];
                        break;
                    case 7:
                        result = sBox8[row, col];
                        break;
                }

                res.Append(Convert.ToString(result, 2).PadLeft(4, '0'));
            }

            return res.ToString();
        }
        public override string Decrypt(string cipherText, string key)
        {
            string key_64 = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            List<string> key1_shifted = new List<string>();
            List<string> key2_shifted = new List<string>();
            //Console.WriteLine("key_64: " + key_64.Count());
            string key_56 = Permutaion(PC_1, key_64, 8, 7);
            //Console.WriteLine("key_56: " + key_56.Count());
            string key1_28 = key_56.Substring(0, 28);
            string key2_28 = key_56.Substring(28, 28);
            CircularShiftLeft(key1_shifted, key2_shifted, key2_28, key1_28);
            List<string> keys_56 = new List<string>();
            for (int i = 0; i < key2_shifted.Count; i++)
            {
                keys_56.Add(key1_shifted[i] + key2_shifted[i]);
            }
            List<string> keys_16 = Add_round_keys(keys_56);
            keys_16 = Enumerable.Reverse(keys_16).ToList();
            //Console.WriteLine("keys_16: " + keys_16.Count);
            string cipher_64 = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string cipher_56 = Permutaion(IInitialPermutation, cipher_64, 8, 8);
            List<string> Left_plain = new List<string>();
            List<string> Right_plain = new List<string>();
            string l_plain = cipher_56.Substring(0, 32);
            string r_plain = cipher_56.Substring(32, 32);
            //Console.WriteLine(cipher_56.Count() + "//////////////////////");
            Left_plain.Add(l_plain);
            Right_plain.Add(r_plain);
            List<string> Separated_plain = new List<string>();
            for (int i = 0; i < 16; i++)
            {
                Left_plain.Add(r_plain);
                Separated_plain.Clear();
                string plain_48 = Permutaion(ExpansionPermutation, r_plain, 8, 6);
                string XOR = "";
                for (int j = 0; j < plain_48.Length; j++)
                {
                    XOR += (keys_16[i][j] ^ plain_48[j]).ToString();
                }
                for (int w = 0; w < XOR.Length; w += 6)
                {
                    string tmp = "";
                    for (int o = w; o < w + 6; o++)
                    {
                        tmp += XOR[o];
                    }
                    Separated_plain.Add(tmp);
                }
                string sbox_result = SBOX(Separated_plain);
                string last_permutation = Permutaion(Permutation, sbox_result, 8, 4);
                XOR = "";
                for (int k = 0; k < last_permutation.Length; k++)
                {
                    XOR += (last_permutation[k] ^ l_plain[k]).ToString();
                }
                l_plain = r_plain;
                r_plain = XOR;
                Right_plain.Add(r_plain);
            }
            string result_16 = Right_plain[16] + Left_plain[16];
            string ciphertext = Permutaion(InitialPermutation_inverse, result_16, 8, 8);
            //Console.WriteLine("c.f" + ciphertext);
            string ct = Convert.ToInt64(ciphertext, 2).ToString("X").PadLeft(16, '0');
            //Console.WriteLine("c.f: " + ct);
            //Console.WriteLine("0x0123456789ABCDEF");
            return "0x" + ct;
        }

        public override string Encrypt(string plainText, string key)
        {

            string key_64 = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            List<string> key1_shifted = new List<string>();
            List<string> key2_shifted = new List<string>();
            string key_56 = Permutaion(PC_1, key_64, 8, 7);
            //Console.WriteLine("key_56: " + key_56.Length);
            string key1_28 = key_56.Substring(0, 28);
            string key2_28 = key_56.Substring(28, 28);
            //Console.WriteLine("key1_28: " + key1_28.Length);
            //Console.WriteLine("key2_28: " + key2_28.Length);
            CircularShiftLeft(key1_shifted, key2_shifted, key2_28, key1_28);
            List<string> keys_56 = new List<string>();
            for (int i = 0; i < key2_shifted.Count; i++)
            {
                keys_56.Add(key1_shifted[i] + key2_shifted[i]);
            }
            List<string> keys_16 = Add_round_keys(keys_56);
            //Console.WriteLine("keys_48: " + keys_16.Count);
            string plain_64 = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string plain_56 = Permutaion(IInitialPermutation, plain_64, 8, 8);
            List<string> Left_plain = new List<string>();
            List<string> Right_plain = new List<string>();
            string l_plain = plain_56.Substring(0, 32);
            string r_plain = plain_56.Substring(32, 32);
            Left_plain.Add(l_plain);
            Right_plain.Add(r_plain);
            List<string> Separated_plain = new List<string>();
            for (int i = 0; i < 16; i++)
            {
                Left_plain.Add(r_plain);
                string XOR = "";
                Separated_plain.Clear();
                //Console.WriteLine("Left_plain: " + Left_plain.Count);
                //Console.WriteLine("Right_plain: " + Right_plain.Count);
                string plain_48 = Permutaion(ExpansionPermutation, r_plain, 8, 6);
                //Console.WriteLine("plain_48: " + plain_48.Length);
                for (int j = 0; j < plain_48.Length; j++)
                {
                    XOR += (keys_16[i][j] ^ plain_48[j]).ToString();
                }
                for (int w = 0; w < XOR.Length; w += 6)
                {
                    string tmp = "";
                    for (int o = w; o < w + 6; o++)
                    {
                        tmp += XOR[o];
                    }
                    //Console.WriteLine("tmp: " + tmp);
                    Separated_plain.Add(tmp);
                }
                string sbox_result = SBOX(Separated_plain);
                string last_permutation = Permutaion(Permutation, sbox_result, 8, 4);
                XOR = "";
                for (int k = 0; k < last_permutation.Length; k++)
                {
                    XOR += (last_permutation[k] ^ l_plain[k]).ToString();
                }
                l_plain = r_plain;
                r_plain = XOR;
                Right_plain.Add(r_plain);
            }
            string result_16 = Right_plain[16] + Left_plain[16];
            string ciphertext = Permutaion(InitialPermutation_inverse, result_16, 8, 8);
            //Console.WriteLine("c.f" + ciphertext);
            string ct = Convert.ToInt64(ciphertext, 2).ToString("X");
            //Console.WriteLine("c.t" + ct);
            return "0x" + ct;
        }
    }
}