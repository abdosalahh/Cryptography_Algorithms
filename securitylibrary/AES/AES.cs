using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public static string[,] sBox = new string[16, 16]
         {   {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b","fe","d7", "ab", "76"},
            {"ca", "82", "c9", "7d" ,"fa", "59", "47", "f0", "ad", "d4", "a2", "af","9c","a4", "72", "c0"},
            {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1","71","d8", "31", "15"},
            {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2","eb","27", "b2", "75"},
            {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3","29","e3", "2f", "84"},
            {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39","4a","4c", "58", "cf"},
            {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f","50","3c", "9f", "a8"},
            {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21","10","ff", "f3", "d2"},
            {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d","64","5d", "19", "73"},
            {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14","de","5e", "0b", "db"},
            {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62","91","95", "e4", "79"},
            {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea","65","7a", "ae", "08"},
            {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f","4b","bd", "8b", "8a"},
            {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9","86","c1", "1d", "9e"},
            {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9","ce","55", "28", "df"},
            {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f","b0","54", "bb", "16"}
         };

        public static string[,] Rcon = new string[4, 10]
        {
            {"01","02","04","08","10","20","40","80","1b","36"},
            {"00","00","00","00","00","00","00","00","00","00"},
            {"00","00","00","00","00","00","00","00","00","00"},
            {"00","00","00","00","00","00","00","00","00","00"}
        };


        private static string[,] TextToMatrix(string text)
        {
            string[,] matrix = new string[4, 4];
            char[] textToCharArr = text.ToCharArray();
            int count = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix[j, i] = textToCharArr[count] + "" + textToCharArr[count + 1];
                    count += 2;
                }
            }
            return matrix;
        }

        public static string MatrixToString(string[,] matrix)
        {
            string Matrixstr = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Matrixstr += matrix[j, i];
                }
            }
            return Matrixstr;
        }


        public static string[,] subBytes(string[,] Matrix, string[,] BOX)
        {
            int numRows = Matrix.GetLength(0);
            int numCols = Matrix.GetLength(1);
            string[,] newBoxResult = new string[numRows, numCols];

            for (int row = 0; row < numRows; row++)
            {
                for (int col = 0; col < numCols; col++)
                {
                    string newMatrix = Matrix[row, col];
                    int rowIndex = int.Parse(newMatrix[0].ToString(), System.Globalization.NumberStyles.HexNumber);
                    int colIndex = int.Parse(newMatrix[1].ToString(), System.Globalization.NumberStyles.HexNumber);
                    newBoxResult[row, col] = BOX[rowIndex, colIndex];
                }
            }

            return newBoxResult;
        }

        public static string[,] ShiftRows(string[,] Matrix)
        {
            int numRows = Matrix.GetLength(0);
            int numCols = Matrix.GetLength(1);

            string[,] newResult = new string[numRows, numCols];

            for (int j = 0; j < numCols; j++)
            {
                newResult[0, j] = Matrix[0, j];
            }

            for (int j = 0; j < numCols; j++)
            {
                newResult[1, j] = Matrix[1, (j + 1) % numCols];
            }

            for (int j = 0; j < numCols; j++)
            {
                newResult[2, j] = Matrix[2, (j + 2) % numCols];
            }

            for (int j = 0; j < numCols; j++)
            {
                newResult[3, j] = Matrix[3, (j + 3) % numCols];
            }

            return newResult;
        }
        public static string[,] MixColumn(string[,] Matrix)
        {
            int rows = Matrix.GetLength(0);
            int cols = Matrix.GetLength(1);

            // Create a new array to hold the mixed columns
            string[,] mixedColumns = new string[rows, cols];

            // The Rijndael MixColumn matrix
            string[,] mixColumnMatrix = new string[,]
            {
                {"02", "03", "01", "01"},
                {"01", "02", "03", "01"},
                {"01", "01", "02", "03"},
                {"03", "01", "01", "02"}
            };

            // Perform the MixColumn operation for each column
            for (int col = 0; col < cols; col++)
            {
                string[] column = new string[rows];
                for (int row = 0; row < rows; row++)
                {
                    column[row] = Matrix[row, col];
                }

                for (int i = 0; i < 4; i++)
                {
                    string mixed = "00";
                    for (int j = 0; j < 4; j++)
                    {
                        string MixColumnMatrix = mixColumnMatrix[i, j];
                        string columnvalue = column[j];

                        if (MixColumnMatrix == "01")
                        {
                            mixed = XOR(mixed, columnvalue);
                        }
                        else if (MixColumnMatrix == "02")
                        {
                            mixed = XOR(mixed, MultiplyByTwo(columnvalue));
                        }
                        else if (MixColumnMatrix == "03")
                        {
                            mixed = XOR(mixed, XOR(MultiplyByTwo(columnvalue), columnvalue));
                        }
                    }
                    mixedColumns[i, col] = mixed;
                }
            }

            return mixedColumns;
        }

        private static string XOR(string a, string b)
        {
            int numA = Convert.ToInt32(a, 16);
            int numB = Convert.ToInt32(b, 16);
            int result = numA ^ numB;
            return result.ToString("X2");
        }

        private static string MultiplyByTwo(string value)
        {
            int num = Convert.ToInt32(value, 16);
            int result = (num << 1) & 0xFF;
            if ((num & 0x80) == 0x80)
            {
                result ^= 0x1B;
            }
            return result.ToString("X2");
        }

        public static string[,] addRoundKey(string[,] Matrix, string[,] roundKey)
        {
            int Numcolmatrix = Matrix.GetLength(0) / 4;

            int numRows = Matrix.GetLength(0);
            int numCols = Matrix.GetLength(1);

            string[,] newResult = new string[numRows, numCols];

            for (int c = 0; c < Numcolmatrix; c++)
            {
                int col = c;

                for (int r = 0; r < 4; r++)
                {
                    int row = r;
                    newResult[row, col] = XOR(Matrix[row, col], roundKey[row, col]);
                    newResult[row, col + 1] = XOR(Matrix[row, col + 1], roundKey[row, col + 1]);
                    newResult[row, col + 2] = XOR(Matrix[row, col + 2], roundKey[row, col + 2]);
                    newResult[row, col + 3] = XOR(Matrix[row, col + 3], roundKey[row, col + 3]);
                }
            }

            return newResult;
        }


        public static string[,] KeysubBytes(string[,] KeyMatrix, string[,] BOX)
        {
            int numRows = KeyMatrix.GetLength(0);
            int numCols = KeyMatrix.GetLength(1);

            string[,] newBoxKey = new string[numRows, numCols];

            for (int row = 0; row < numRows; row++)
            {
                for (int col = 0; col < numCols; col++)
                {
                    string newKeyMatrix = KeyMatrix[row, col];
                    int rowIndex = Convert.ToInt32(newKeyMatrix.Substring(0, 1), 16);
                    int colIndex = Convert.ToInt32(newKeyMatrix.Substring(1, 1), 16);
                    newBoxKey[row, col] = BOX[rowIndex, colIndex];
                }
            }

            return newBoxKey;
        }

        public static string[,] GenerateRoundKey(int round, string mainKey, string[,] BOX)
        {
            string[,] Key = new string[4, 4];
            string[,] MKey = new string[4, 4];
            int index = 2;
            while (index != mainKey.Length)
            {
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        Key[j, i] = mainKey.Substring(index, 2);
                        MKey[j, i] = mainKey.Substring(index, 2);
                        index += 2;
                    }
                }
            }

            //step1 Rot
            string temp = Key[0, 3];
            Key[0, 3] = Key[1, 3];
            Key[1, 3] = Key[2, 3];
            Key[2, 3] = Key[3, 3];
            Key[3, 3] = temp;

            //step2 sub
            string[,] KeyV2 = new string[4, 4];
            KeyV2 = KeysubBytes(Key, BOX);

            //step3
            string[,] NewRoundKey = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (j == 0)
                    {
                        string a = XOR(MKey[i, j], KeyV2[i, 3]);
                        if (a.Length == 1)
                        {
                            a = "0" + a;
                        }
                        string b = XOR(a, Rcon[i, round]);
                        if (b.Length == 1)
                        {
                            b = "0" + b;
                        }
                        NewRoundKey[i, j] = b;
                    }
                    else
                    {
                        string x = MKey[i, j];
                        string y = NewRoundKey[i, j - 1];
                        string a = XOR(x, y);
                        if (a.Length == 1)
                        {
                            a = "0" + a;
                        }
                        NewRoundKey[i, j] = a;
                    }
                }
            }
            return NewRoundKey;
        }



        public static string[,] GetRoundKeyByIndex(string[,,] Allkeys, int i)
        {
            string[,] roundKey = new string[4, 4];
            for (int j = 0; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                {
                    roundKey[j, k] = Allkeys[i, j, k];
                }
            }
            return roundKey;
        }

        public static int mod(int x, int m)
        {
            int r = x % m;
            return r < 0 ? r + m : r;
        }

        public static string[,] UnShift(string[,] Matrix)
        {
            string[,] UnShiftedMatrix = new string[4, 4];
            int numCols = 4;
            for (int i = 0; i < numCols; i++)
            {
                UnShiftedMatrix[0, i] = Matrix[0, i];
            }
            for (int j = 0; j < numCols; j++)
            {
                UnShiftedMatrix[1, j] = Matrix[1, mod((j - 1), numCols)];
            }

            for (int j = 0; j < numCols; j++)
            {
                UnShiftedMatrix[2, j] = Matrix[2, mod((j - 2), numCols)];
            }

            for (int j = 0; j < numCols; j++)
            {
                UnShiftedMatrix[3, j] = Matrix[3, mod((j - 3), numCols)];
            }
            return UnShiftedMatrix;
        }

        public static string[,] UnSubBytes(string[,] Matrix, string[,] BOX)
        {
            int numRows = Matrix.GetLength(0);
            int numCols = Matrix.GetLength(1);
            string[,] newBoxResult = new string[numRows, numCols];
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < numCols; j++)
                {
                    for (int k = 0; k < 16; k++)
                    {
                        for (int l = 0; l < 16; l++)
                        {
                            if (Matrix[i, j].ToLower() == BOX[k, l])
                            {
                                newBoxResult[i, j] = k.ToString("X") + l.ToString("X");
                            }
                        }
                    }
                }
            }
            return newBoxResult;
        }
        private static readonly byte[,] InvMixColumnMatrix =
        {
            { 0x0e, 0x0b, 0x0d, 0x09 },
            { 0x09, 0x0e, 0x0b, 0x0d },
            { 0x0d, 0x09, 0x0e, 0x0b },
            { 0x0b, 0x0d, 0x09, 0x0e }
        };

        private static string[,] InvMixColumns(string[,] matrix)
        {
            int rows = matrix.GetLength(0);
            int cols = matrix.GetLength(1);

            // Create a new matrix to hold the result.
            string[,] result = new string[rows, cols];

            // Loop through each column of the matrix.
            for (int col = 0; col < cols; col++)
            {
                // Create a new column array to hold the current column.
                string[] column = new string[4];

                // Copy the values from the current column of the input matrix to the new column array.
                for (int row = 0; row < 4; row++)
                {
                    column[row] = matrix[row, col];
                }

                // Perform the InvMixColumn operation on the new column array.
                column = InvMixColumn(column);

                // Copy the values from the new column array to the corresponding column in the result matrix.
                for (int row = 0; row < 4; row++)
                {
                    result[row, col] = column[row];
                }
            }

            return result;
        }

        private static string[] InvMixColumn(string[] column)
        {
            // Create a new column array to hold the result.
            string[] result = new string[4];

            // Loop through each row of the InvMixColumnMatrix.
            for (int row = 0; row < 4; row++)
            {
                // Multiply the current row of the InvMixColumnMatrix by the corresponding value in the input column.
                int value = Multiply(InvMixColumnMatrix[row, 0], column[0]) ^
                            Multiply(InvMixColumnMatrix[row, 1], column[1]) ^
                            Multiply(InvMixColumnMatrix[row, 2], column[2]) ^
                            Multiply(InvMixColumnMatrix[row, 3], column[3]);

                // Convert the result to a hex string and add it to the result array.
                result[row] = value.ToString("X2");
            }

            return result;
        }

        private static int Multiply(int a, string b)
        {
            // Convert the input string to an integer.
            int num = int.Parse(b, System.Globalization.NumberStyles.HexNumber);

            // Perform the multiplication operation in the Galois field.
            int result = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((a & (1 << i)) != 0)
                {
                    result ^= (num << i);
                }
            }

            // Reduce the result in the Galois field.
            for (int i = 14; i >= 8; i--)
            {
                if ((result & (1 << i)) != 0)
                {
                    result ^= (0x11B << (i - 8));
                }
            }

            return result;
        }

        public override string Encrypt(string plainText, string key)
        {
            string[,] Matrix = TextToMatrix(plainText);
            string[,] matrixKey = TextToMatrix(key);
            string[,] newMatrix = addRoundKey(Matrix, matrixKey);
            string[,] shiftMatrix = new string[4, 4];
            string[,] subMatrix = new string[4, 4];
            string[,] mixMatrix = new string[4, 4];
            string[,] roundKey = new string[4, 4];
            for (int i = 0; i < 9; i++)
            {
                subMatrix = subBytes(newMatrix, sBox);
                shiftMatrix = ShiftRows(subMatrix);
                mixMatrix = MixColumn(shiftMatrix);
                roundKey = GenerateRoundKey(i, key, sBox);
                key = MatrixToString(roundKey);
                newMatrix = addRoundKey(mixMatrix, roundKey);
            }

            string[,] finalMatrix = new string[4, 4];
            string[,] finalShiftMatrix = new string[4, 4];
            string[,] finalsubMatrix = new string[4, 4];

            finalsubMatrix = subBytes(newMatrix, sBox);
            finalShiftMatrix = ShiftRows(finalsubMatrix);
            roundKey = GenerateRoundKey(9, key, sBox);
            finalMatrix = addRoundKey(finalShiftMatrix, roundKey);

            string cipher = MatrixToString(finalMatrix);
            return cipher;
        }

        public override string Decrypt(string cipherText, string key)
        {
            string[,] FinalMatrix = TextToMatrix(cipherText);
            string[,] matrixKey = TextToMatrix(key);
            string[,,] Allkeys = new string[10, 4, 4];
            string[,] roundKey = new string[4, 4];
            for (int i = 0; i < 10; i++)
            {
                roundKey = GenerateRoundKey(i, key, sBox);
                key = MatrixToString(roundKey);
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        Allkeys[i, j, k] = roundKey[j, k];
                    }
                }
            }

            string[,] FinalShiftMatrix = new string[4, 4];
            string[,] FinalsubMatrix = new string[4, 4];
            string[,] newMatrix = new string[4, 4];
            string[,] mixMatrix = new string[4, 4];
            roundKey = GetRoundKeyByIndex(Allkeys, 9);
            FinalShiftMatrix = addRoundKey(FinalMatrix, roundKey);
            FinalsubMatrix = UnShift(FinalShiftMatrix);
            newMatrix = UnSubBytes(FinalsubMatrix, sBox);
            for (int i = 8; i >= 0; i--)
            {
                roundKey = GetRoundKeyByIndex(Allkeys, i);
                mixMatrix = addRoundKey(newMatrix, roundKey);
                FinalShiftMatrix = InvMixColumns(mixMatrix);
                FinalsubMatrix = UnShift(FinalShiftMatrix);
                newMatrix = UnSubBytes(FinalsubMatrix, sBox);
            }

            string[,] FinalDecribt = addRoundKey(newMatrix, matrixKey);
            string Plain = MatrixToString(FinalDecribt);
            return Plain;
        }
    }
}
