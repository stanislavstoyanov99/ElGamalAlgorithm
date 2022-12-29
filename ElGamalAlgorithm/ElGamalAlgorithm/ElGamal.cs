namespace ElGamalAlgorithm
{
    using System;
    using System.IO;
    using System.Numerics;
    using System.Text;

    public class ElGamal
    {
        private const int RandomExponentMax = 100;

        public string GenerateKeys(string generatorFileName)
        {
            var lines = File.ReadAllLines(generatorFileName);
            var prime = BigInteger.Parse(lines[0]);
            var generator = BigInteger.Parse(lines[1]);

            var random = new Random();
            var aliceK = random.Next(1, RandomExponentMax);

            // Alice Public Key - generator to random number K (g ^ aliceK)
            var alicePublicKey = BigInteger.ModPow(generator, aliceK, prime);

            var output = prime + Environment.NewLine + generator + Environment.NewLine;
            var privateKeyText = output + aliceK + Environment.NewLine;
            var publicKeyText = output + alicePublicKey + Environment.NewLine;

            var privateKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), FileNames.PrivateKey);
            var publicKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), FileNames.PublicKey);

            var sb = new StringBuilder();
            sb.AppendLine(
                $"Prime number: {prime}" + Environment.NewLine +
                $"Generator: {generator}" + Environment.NewLine +
                $"Alice Random number: {aliceK}" + Environment.NewLine +
                "Private Key:" + Environment.NewLine + $"{privateKeyText}");
            sb.AppendLine("Public Key:" + Environment.NewLine + $"{publicKeyText}");

            File.WriteAllText(privateKeyPath, privateKeyText);
            File.WriteAllText(publicKeyPath, publicKeyText);

            return sb.ToString();
        }

        public string Encrypt(string publicKeyFileName, string messageFileName)
        {
            var publicKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), publicKeyFileName);
            var publicKeyLines = File.ReadAllLines(publicKeyPath);
            var messageLines = File.ReadAllLines(messageFileName);

            var message = BigInteger.Parse(messageLines[0]);
            var prime = BigInteger.Parse(publicKeyLines[0]);

            if (message >= prime)
            {
                throw new ArgumentException("m < p condition not met");
            }

            var generator = BigInteger.Parse(publicKeyLines[1]);
            var alicePublicKey = BigInteger.Parse(publicKeyLines[2]);

            var random = new Random();
            var bobK = random.Next(1, RandomExponentMax);

            // Bob's public key - generator to random number K (g ^ bobK)
            var bobPublicKey = BigInteger.ModPow(generator, bobK, prime);

            // Common encryption key - (generator ^ aliceK) ^ bobK
            var encryptionKey = BigInteger.ModPow(alicePublicKey, bobK, prime);

            var encryptedMessage = (message * encryptionKey) % prime;
            var output = bobPublicKey + Environment.NewLine + encryptedMessage + Environment.NewLine;

            var encryptedTextPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), FileNames.EncryptedText);

            var sb = new StringBuilder();
            sb.AppendLine($"Bob's public key: {bobPublicKey}");
            sb.AppendLine($"Bob's Random number: {bobK}");
            sb.AppendLine($"Encrypted message: {encryptedMessage}");

            File.WriteAllText(encryptedTextPath, output);

            return sb.ToString();
        }

        public string Decrypt(string privateKeyFileName, string encryptedMessageFileName)
        {
            var privateKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), privateKeyFileName);
            var encryptedMessagePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), encryptedMessageFileName);
            var privateKeyLines = File.ReadAllLines(privateKeyPath);
            var encryptedMessageLines = File.ReadAllLines(encryptedMessagePath);

            var prime = BigInteger.Parse(privateKeyLines[0]);
            var generator = BigInteger.Parse(privateKeyLines[1]);

            var bobPublicKey = BigInteger.Parse(encryptedMessageLines[0]);
            var bobK = 1;
            while (true)
            {
                // Loop till Bob K is found
                if (BigInteger.ModPow(generator, bobK, prime) == bobPublicKey)
                {
                    break;
                }

                bobK++;
            }

            // Alice public key => generator ^ aliceK
            var aliceK = BigInteger.Parse(privateKeyLines[2]);
            var alicePublicKey = BigInteger.ModPow(generator, aliceK, prime);

            // encryption key => (generator ^ aliceK) ^ bobK
            var encryptionKey = BigInteger.ModPow(alicePublicKey, bobK, prime);

            var encryptedMessage = BigInteger.Parse(encryptedMessageLines[1]);
            var encryptionKeyInverse = BigInteger.ModPow(encryptionKey, prime - 2, prime);
            var decryptedMessage = (encryptedMessage * encryptionKeyInverse) % prime;

            var output = decryptedMessage + Environment.NewLine;

            var decryptedTextPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), FileNames.DecryptedText);

            var sb = new StringBuilder();
            sb.AppendLine($"Decrypted message: {decryptedMessage}");

            File.WriteAllText(decryptedTextPath, output);

            return sb.ToString();
        }

        public string Sign(string privateKeyFileName, string messageFileName)
        {
            var privateKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), privateKeyFileName);
            var privateKeyLines = File.ReadAllLines(privateKeyPath);
            var messageLines = File.ReadAllLines(messageFileName);

            var prime = BigInteger.Parse(privateKeyLines[0]);
            var generator = BigInteger.Parse(privateKeyLines[1]);
            var aliceK = BigInteger.Parse(privateKeyLines[2]);
            var message = BigInteger.Parse(messageLines[0]);

            var random = new Random();

            // generate r
            int k;
            while (true)
            {
                var primeInt = prime < int.MaxValue ? (int)prime : int.MaxValue;
                k = random.Next(1, primeInt);
                var relativelyPrime = BigInteger.GreatestCommonDivisor(k, prime - 1) == 1;
                if (relativelyPrime)
                {
                    break;
                }
            }
            var r = BigInteger.ModPow(generator, k, prime);

            // generate x
            var kInverse = this.MultiplicativeInverse(k, prime - 1);
            var mod = prime - 1;

            // ensure modulo operations are performed on positive numbers
            // by adding a "span" (modulo bound * any high-enough multiplier)
            var x1 = message - (aliceK * r) + (mod * 10_000);
            var x = (x1 * kInverse) % mod;

            var output = r + Environment.NewLine + x + Environment.NewLine;

            var signaturePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), FileNames.Signature);

            var sb = new StringBuilder();
            sb.AppendLine("Signature:" + Environment.NewLine + $"{output}");

            File.WriteAllText(signaturePath, output);

            return sb.ToString();
        }

        public string VerifySignature(string publicKeyFileName, string messageFileName, string signatureFileName)
        {
            var publicKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), publicKeyFileName);
            var publicKeyLines = File.ReadAllLines(publicKeyPath);
            var messageLines = File.ReadAllLines(messageFileName);
            var signaturePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), signatureFileName);
            var signatureLines = File.ReadAllLines(signaturePath);

            var prime = BigInteger.Parse(publicKeyLines[0]);
            var generator = BigInteger.Parse(publicKeyLines[1]);
            var publicKey = BigInteger.Parse(publicKeyLines[2]);
            var message = BigInteger.Parse(messageLines[0]);
            var r = BigInteger.Parse(signatureLines[0]);
            var x = BigInteger.Parse(signatureLines[1]);

            var left = BigInteger.ModPow(generator, message, prime);
            var right = (BigInteger.ModPow(publicKey, r, prime) * BigInteger.ModPow(r, x, prime)) % prime;

            var output = string.Empty;
            if (r >= 1 && r < prime && left == right)
            {
                output = "Valid signature!";
            }
            else
            {
                output = "Invalid signature!";
            }

            var verifySignaturePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), FileNames.VerifySignature);

            File.WriteAllText(verifySignaturePath, output);

            return output;
        }

        private BigInteger MultiplicativeInverse(BigInteger a, BigInteger m)
        {
            BigInteger x0 = 0;
            BigInteger x1 = 1;

            var m0 = m;

            if (m == 0)
            {
                return 1;
            }

            while (a > 1)
            {
                var q = a / m;
                var t = m;
                m = a % m;
                a = t;

                t = x0;
                x0 = x1 - q * x0;
                x1 = t;
            }

            if (x1 < 0)
            {
                x1 += m0;
            }

            return x1;
        }
    }
}
