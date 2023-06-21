using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Encrypt(string plainText, string key)
        {
            //initialize attributes
            bool ishexa = false;
            string cipherText = "";
            // Convert hex input to ASCII
            if (plainText.StartsWith("0x"))
            {
                plainText = ConvHexaToAscii(plainText.Substring(2));
                ishexa = true;
            }
            if (key.StartsWith("0x"))
            {
                key = ConvHexaToAscii(key.Substring(2));
                ishexa = true;
            }
            // Convert input to character arrays
            char[] plain = plainText.ToCharArray();
            var keyChars = key.ToCharArray();
            var InitK = Enumerable.Range(0, 256).Select(i => (char)i).ToArray();
            var C = new char[256];
            for (int i = 0; i < 256; i++)
            {
                C[i] = keyChars[i % keyChars.Length];
            }
            int j = 0;
            char temp;
            for (int i = 0; i < 256; i++)
            {
                j = (j + InitK[i] + C[i]) % 256;
                temp = InitK[i];
                InitK[i] = InitK[j];
                InitK[j] = temp;
            }
            // Generate the subkeys inline
            int x = 0, y = 0;
            char[] subKeys = new char[plain.Length];
            char subTemp;
            for (int i = 0; i < plain.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + InitK[x]) % 256;
                subTemp = InitK[x];
                InitK[x] = InitK[y];
                InitK[y] = subTemp;
                subKeys[i] = InitK[(InitK[x] + InitK[y]) % 256];
                cipherText += (char)(plain[i] ^ subKeys[i]);
            }
            // Convert output to hex if necessary
            if (ishexa)
            {
                return "0x" + ConvASCIIToHexa(cipherText);
            }
            return cipherText;
        }
        public override string Decrypt(string cipherText, string key)
        {
            //initialize attributes
            bool isHexa = false;
            string plainText = cipherText;
            // Convert hex input to ASCII
            if (cipherText.StartsWith("0x"))
            {
                plainText = ConvHexaToAscii(cipherText.Substring(2));
                isHexa = true;
            }
            if (key.StartsWith("0x"))
            {
                key = ConvHexaToAscii(key.Substring(2));
                isHexa = true;
            }
            // Convert input to character arrays
            char[] cipher = plainText.ToCharArray();
            var keyChars = key.ToCharArray();
            var InitK = Enumerable.Range(0, 256).Select(i => (char)i).ToArray();
            var C = new char[256];
            for (int i = 0; i < 256; i++)
            {
                C[i] = keyChars[i % keyChars.Length];
            }
            int j = 0;
            char temp;
            for (int i = 0; i < 256; i++)
            {
                j = (j + InitK[i] + C[i]) % 256;
                temp = InitK[i];
                InitK[i] = InitK[j];
                InitK[j] = temp;
            }

            int x = 0, y = 0;
            char subKey;
            string plain = "";
            // Decrypt the Cipher using the generated subkeys
            for (int i = 0; i < cipher.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + InitK[x]) % 256;
                temp = InitK[x];
                InitK[x] = InitK[y];
                InitK[y] = temp;
                subKey = InitK[(InitK[x] + InitK[y]) % 256];
                plain += (char)(cipher[i] ^ subKey);
            }
            if (isHexa)
            {
                return "0x" + ConvASCIIToHexa(plain);
            }
            return plain;
        }
        public static string ConvASCIIToHexa(string ASC)
        {
            var HEXA = new StringBuilder();
            for (int i = 0; i < ASC.Length; i++)
            {
                int temp = (int)ASC[i];
                string part = temp.ToString("X2");
                HEXA.Append(part);
            }
            return HEXA.ToString();
        }
        public static string ConvHexaToAscii(string HEXA)
        {
            var ASC = new StringBuilder();
            for (int i = 0; i < HEXA.Length; i += 2)
            {
                string part = HEXA.Substring(i, 2);
                int charCode = Convert.ToInt32(part, 16);
                char ch = (char)charCode;
                ASC.Append(ch);
            }
            return ASC.ToString();
        }
    }
}
