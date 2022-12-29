namespace ElGamalAlgorithm
{
    using System;

    public class StartUp
    {
        public static void Main(string[] args)
        {
            const string parameterHelp = " Try:" +
                                         "\n-k -- generate keys" +
                                         "\n-e -- encrypt text" +
                                         "\n-d -- decrypt text" +
                                         "\n-s -- generate signature" +
                                         "\n-v -- verify signature";

            if (args.Length != 1 || args[0] == null)
            {
                Console.WriteLine("Missing action parameter!" + parameterHelp);
                return;
            }

            try
            {
                var elGamal = new ElGamal();

                switch (args[0])
                {
                    case "-k":
                        var keys = elGamal.GenerateKeys(FileNames.Generator);
                        Console.WriteLine(keys);
                        break;

                    case "-e":
                        var encryptedMessage = elGamal.Encrypt(FileNames.PublicKey, FileNames.PlainText);
                        Console.WriteLine(encryptedMessage);
                        break;

                    case "-d":
                        var decryptedMessage = elGamal.Decrypt(FileNames.PrivateKey, FileNames.EncryptedText);
                        Console.WriteLine(decryptedMessage);
                        break;

                    case "-s":
                        var signature = elGamal.Sign(FileNames.PrivateKey, FileNames.MessageText);
                        Console.WriteLine(signature);
                        break;

                    case "-v":
                        var verifiedSignature = elGamal.VerifySignature(FileNames.PublicKey, FileNames.MessageText, FileNames.Signature);
                        Console.WriteLine(verifiedSignature);
                        break;

                    default:
                        Console.WriteLine("Wrong action parameter!" + parameterHelp);
                        break;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }
}
