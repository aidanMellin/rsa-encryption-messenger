// Author: Aidan Mellin

using System.Net.Http;
using Newtonsoft.Json;
using System.Text;
using System.Numerics;
namespace Messenger{

    /// <summary>
    /// Class representing a set of private and public keys.
    /// </summary>
    class Keys{
        public string? privateKey { get; set; }
        public string? publicKey { get; set; }
    }

    /// <summary>
    /// Class containing key information for public/private key operations.
    /// </summary>
    class KeyInfo{
        public int e { get; }
        public int n { get; }

        public BigInteger E { get; }
        public BigInteger N { get; }

        public KeyInfo(int e, BigInteger E, int n, BigInteger N){
            this.e = e;
            this.n = n;

            this.E = E;
            this.N = N;
        }
    }
    
    /// <summary>
    /// Class representing a public key and its associated email.
    /// </summary>
    class PublicKey{
        public string? key { get; set; }
        public string? email { get; set; }
    }

    /// <summary>
    /// Class representing a private key and its associated emails.
    /// </summary>
    class PrivateKey{
        public string? key { get; set; }
        public List<string>? email { get; set; }
    }

    /// <summary>
    /// Class representing an email message with content.
    /// </summary>
    class Message{
        public string? email { get; set; }
        public string? content { get; set; }
    }

    class Messenger{
        private HttpClient client = new();
        private Keys keys = new();
        private readonly string privKeyFile = "private.key";
        private readonly string pubKeyFile = "public.key";
        private Messenger(){
            HttpClient client = new HttpClient();
            Keys keys = new Keys();
        }

        static void Main(string[] args){
            bool validLength = args.Length == 2 || args.Length == 3;
            switch(validLength){
                case true:
                    break;
                default:
                    Usage();
                    break;
            }

            var messenger = new Messenger();
            string command = args[0].ToLower();
            switch(command){
                case "keygen":
                    var bits = Int32.Parse(args[1]);
                    messenger.genKey(bits);
                    break;
                case "sendkey":
                    messenger.sendKey(args[1]);
                    break;
                case "getkey":
                    messenger.getKey(args[1]);
                    break;
                case "getmsg":
                    messenger.getMsg(args[1]);
                    break;
                case "sendmsg":
                    messenger.sendMsg(args[1], args[2]);
                    break;
                default:
                    Usage();
                    break;
            }
        }

        /// <summary>
        /// Generates public and private key pair.
        /// </summary>
        private void genKey(int keysize){
            var pSize = (int)((keysize / 2) - (keysize * 0.2));
            var qSize = keysize - pSize;

            var pVal = new PrimeGen(pSize);
            var qVal = new PrimeGen(qSize);
            BigInteger p = pVal.GetPrime();
            BigInteger q = qVal.GetPrime();

            BigInteger N = p*q;
            byte[] bigNBytes = N.ToByteArray();
            byte[] littleNBytes = BitConverter.GetBytes(bigNBytes.Length);
            Array.Reverse(littleNBytes);

            var r = (p - 1) * (q - 1);

            BigInteger E = new BigInteger(65557);
            byte[] bigEBytes = E.ToByteArray();
            byte[] littleEBytes = BitConverter.GetBytes(bigEBytes.Length);
            Array.Reverse(littleEBytes);

            var D = inverseMod(E, r);
            byte[] bigDBytes = D.ToByteArray();
            byte[] littleDBytes = BitConverter.GetBytes(bigDBytes.Length);
            Array.Reverse(littleDBytes);

            byte[] PublicBytes = new byte[littleEBytes.Length + bigEBytes.Length + littleNBytes.Length + bigNBytes.Length];
            Buffer.BlockCopy(littleEBytes, 0, PublicBytes, 0, littleEBytes.Length);
            Buffer.BlockCopy(bigEBytes, 0, PublicBytes, littleEBytes.Length, bigEBytes.Length);
            Buffer.BlockCopy(littleNBytes, 0, PublicBytes, littleEBytes.Length+bigEBytes.Length, littleNBytes.Length);
            Buffer.BlockCopy(bigNBytes, 0, PublicBytes, littleEBytes.Length+bigEBytes.Length+littleNBytes.Length, bigNBytes.Length);
            var PublicEncoded = Convert.ToBase64String(PublicBytes);

            var publicKey = new PublicKey{
                key = PublicEncoded
            };
            string publicJson = JsonConvert.SerializeObject(publicKey, Formatting.Indented);
            File.WriteAllText(pubKeyFile, publicJson);

            byte[] PrivateBytes = new byte[littleDBytes.Length + bigDBytes.Length + littleNBytes.Length + bigNBytes.Length];
            Buffer.BlockCopy(littleDBytes, 0, PrivateBytes, 0, littleDBytes.Length);
            Buffer.BlockCopy(bigDBytes, 0, PrivateBytes, littleDBytes.Length, bigDBytes.Length);
            Buffer.BlockCopy(littleNBytes, 0, PrivateBytes, littleDBytes.Length+bigDBytes.Length, littleNBytes.Length);
            Buffer.BlockCopy(bigNBytes, 0, PrivateBytes, littleDBytes.Length+bigDBytes.Length+littleNBytes.Length, bigNBytes.Length);
            var PrivateEncoded = Convert.ToBase64String(PrivateBytes);

            var privateKey = new PrivateKey{
                key = PrivateEncoded
            };
            string privateJson = JsonConvert.SerializeObject(privateKey, Formatting.Indented);
            File.WriteAllText(privKeyFile, privateJson);
        }

        /// <summary>
        /// Retrieves public key for the given email from the server.
        /// </summary>
        private void getKey(string email){
            try{
                string endpoint = $"http://kayrun.cs.rit.edu:5000/Key/{email}";
                string filename = $"{email}.key";

                var response = client.GetStringAsync(endpoint);
                var responseDeSerialize = JsonConvert.DeserializeObject<PublicKey>(response.Result);
                string responseJson = JsonConvert.SerializeObject(responseDeSerialize, Formatting.Indented);
                File.WriteAllText(filename, responseJson);
            }
            catch (HttpRequestException e){
                Console.WriteLine($"Exception: {e.Message}\n");
                Environment.Exit(0);
            }
        }


        /// <summary>
        /// Encrypts a message and sends it to the server.
        /// </summary>
        private void sendMsg(string email, string plaintext){
            string filename = $"{email}.key";
            string endpoint = $"http://kayrun.cs.rit.edu:5000/Message/{email}";
            try{
                var publicKeyFileContent = File.ReadAllText(filename);
                var publicKeyObject = JsonConvert.DeserializeObject<PublicKey>(publicKeyFileContent);
                if (publicKeyObject is null || publicKeyObject.key is null){
                    Console.WriteLine($"Key does not exist for email: {email}\n");
                    Environment.Exit(0);
                }
                byte[] bytesP = Encoding.UTF8.GetBytes(plaintext);
                BigInteger bigIntP = new BigInteger(bytesP);
                KeyInfo kInfo = decode(publicKeyObject.key);
                BigInteger pEnc = BigInteger.ModPow(bigIntP, kInfo.E, kInfo.N);
                byte[] pEncBytes = pEnc.ToByteArray();
                var encodedMessage = Convert.ToBase64String(pEncBytes);
                Message message = new Message();
                message.email = email;
                message.content = encodedMessage;
                string messageStr = JsonConvert.SerializeObject(message, Formatting.Indented);
                var content = new StringContent(messageStr, Encoding.UTF8, "application/json");
                try{
                    var response = client.PutAsync(endpoint, content);
                    if(!response.Result.IsSuccessStatusCode){
                        Console.WriteLine("Unsuccessful write to server.\n");
                        Environment.Exit(0);
                    }
                }
                catch (HttpRequestException e){
                    Console.WriteLine($"Exception: {e.Message}\n");
                    Environment.Exit(0);
                }
            }
            catch (IOException){
                Console.WriteLine($"Key does not exist for {email}\n");
                Environment.Exit(0);
            }
            Console.WriteLine("Message written\n");
        }

        /// <summary>
        /// Retrieves encrypted message from the server and decrypts it.
        /// </summary>
        private void getMsg(string email){
            string endpoint = $"http://kayrun.cs.rit.edu:5000/Message/{email}";
            var privateKeyFileContent = File.ReadAllText(privKeyFile);
            var privateKeyObject = JsonConvert.DeserializeObject<PrivateKey>(privateKeyFileContent);
            if (privateKeyObject is null || privateKeyObject.email is null || !privateKeyObject.email.Contains(email) || privateKeyObject.key is null){
                Console.WriteLine($"Unable to decode.\n");
                Environment.Exit(0);
            }
            try{
                var response = client.GetStringAsync(endpoint);
                var encMessage = JsonConvert.DeserializeObject<Message>(response.Result);
                if (encMessage is null || encMessage.content is null){
                    Console.WriteLine("Server does not contain message.\n");
                    Environment.Exit(0);
                }
                byte[] bytesMessage = Convert.FromBase64String(encMessage.content);
                BigInteger C = new BigInteger(bytesMessage);
                KeyInfo kInfo = decode(privateKeyObject.key);
                var bigIntegerP = BigInteger.ModPow(C, kInfo.E, kInfo.N);
                var bytesP = bigIntegerP.ToByteArray();
                var decoded = Encoding.UTF8.GetString(bytesP);
                Console.WriteLine($"{decoded}\n");
            }
            catch (HttpRequestException e){
                Console.WriteLine($"Exception: {e.Message}\n");
            }
        }

        /// <summary>
        /// Sends public key to the server and associates it with an email.
        /// </summary>
        private void sendKey(string email){
            string endpoint = $"http://kayrun.cs.rit.edu:5000/Key/{email}";
            try{
                var publicKeyFileContent = File.ReadAllText(pubKeyFile);
                var publicKeyObject = JsonConvert.DeserializeObject<PublicKey>(publicKeyFileContent);
                var privateKeyFileContent = File.ReadAllText(privKeyFile);
                var privateKeyObject = JsonConvert.DeserializeObject<PrivateKey>(privateKeyFileContent);

                if (publicKeyObject is null || publicKeyObject.key is null || privateKeyObject is null){
                    Console.WriteLine($"File empty or no key value.\n");
                    Environment.Exit(0);
                }

                publicKeyObject.email = $"{email}";
                var publicKeyString = JsonConvert.SerializeObject(publicKeyObject);
                var content = new StringContent(publicKeyString, Encoding.UTF8, "application/json");
                var response = client.PutAsync(endpoint, content);
                if(!response.Result.IsSuccessStatusCode){
                    Console.WriteLine("Program was unsuccessful when writing public key to server.\n");
                    Environment.Exit(0);
                }

                if (privateKeyObject.email is null){
                    List<string> listEmail = new List<string>();
                    listEmail.Add(email);
                    privateKeyObject.email = listEmail;
                }
                else{
                    privateKeyObject.email.Add(email);
                }
                string privateKeyString = JsonConvert.SerializeObject(privateKeyObject, Formatting.Indented);
                File.WriteAllText(privKeyFile, privateKeyString);
            }
            catch (HttpRequestException e){
                Console.WriteLine($"Exception: {e.Message}\n");
                Environment.Exit(0);
            }
            Console.WriteLine("Key saved\n");
        }

        /// <summary>
        /// Decodes a given base64 key string and returns a KeyInfo object.
        /// </summary>
        private KeyInfo decode(string key){
            byte[] bytes = Convert.FromBase64String(key);
            var lowerEBytes = bytes.Take(4).ToArray();
            Array.Reverse(lowerEBytes);
            var e = BitConverter.ToInt32(lowerEBytes);

            var upperEBytes = bytes.Skip(4).Take(e).ToArray();
            var E = new BigInteger(upperEBytes);

            var lowerNBytes = bytes.Skip(4+e).Take(4).ToArray();
            Array.Reverse(lowerNBytes);
            var n = BitConverter.ToInt32(lowerNBytes);

            var upperNBytes = bytes.Skip(4+e+4).Take(n).ToArray();
            var N = new BigInteger(upperNBytes);
            return new KeyInfo(e, E, n, N);
        }

        /// <summary>
        /// Calculates the modular inverse of two BigIntegers.
        /// </summary>
        static BigInteger inverseMod(BigInteger a, BigInteger n){
            BigInteger i = n, v = 0, d = 1;
            while (a > 0){
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) 
                v = (v + n) % n;
            return v;
        }

        /// <summary>
        /// Displays usage instructions and exits the program.
        /// </summary>
        private static void Usage(){
            Console.WriteLine("Usage:\n\tdotnet run \n\t\t- keygen [keysize]\n\t\t- sendkey/getKey/getMsg [email]\n\t\t- sendMsg [email] [plaintext]");
            Environment.Exit(0);
        }
    }
}

