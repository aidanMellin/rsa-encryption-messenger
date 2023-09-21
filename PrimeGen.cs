using System;
using System.IO;
using System.Threading;
using System.Numerics;
using System.Diagnostics;

using System.Threading.Tasks;
using System.Collections.Generic;

namespace Messenger{
    class PrimeGen{
        Stopwatch watch = new Stopwatch();
        int bits;
        int count;
        private static readonly object primeLock = new ();

        
        public PrimeGen(int pSize){
            this.bits = (pSize/8);
            this.count = 1;
        }

        /*
        * Iterate until false condition
        */
        private static IEnumerable<bool> IterateUntilFalse(Func<bool> condition){
            while(condition()) yield return true;
        }

        /*
        * Primary driver code
        */
        // static void Main(string[] args){
        //     PrimeGen pg = new PrimeGen();
        //     pg.usage(args);
        //     Console.WriteLine($"BitLength: {pg.bits*8} bits");
        //     pg.watch = Stopwatch.StartNew();
        //     pg.findPrimes();
        //     pg.watch.Stop();
        //     Console.WriteLine($"Time to Generate: {pg.watch.Elapsed} ms");
        // }

        /*
        * Evaluate number of primes determined by count passed through command line
        */
        public BigInteger GetPrime(){
            int counter = 0;
            var pNum = BigInteger.Zero;

            Parallel.ForEach(IterateUntilFalse(() => counter < this.count), _ => {
                var num = this.getRandomBigInt();
                if (BigInteger.ModPow(num, 1, 2) == 0){
                    return;
                }
                if (!num.isProbablyPrime()){
                    return;
                }
                lock(primeLock){
                    if(counter >= this.count){
                        return;
                    }
                    counter += 1;
                    pNum = num;
                }
            });
            return pNum;
        }

        /*
        * Get a Random BigInt based off bits passed at runtime
        */
        private BigInteger getRandomBigInt(){
            Random random = new Random();
            byte[] bytes = new byte[this.bits];
            random.NextBytes(bytes);
            bytes [bytes.Length - 1] &= (byte)0x7F; // Force sign bit to be positive
            return new BigInteger(bytes);
        }

        /*
        * Parse input into valid integers, error if not
        */
        private int parseInput(string input){
            try
            {
                int numVal = Int32.Parse(input);
                return numVal;
            }
            catch (FormatException)
            {
                Console.WriteLine($"Unable to parse '{input}'");
                System.Environment.Exit(1);
                return 0; //Just to quiet the warnings
            }
        }

        /*
        * Determine inputs fit criteria for command line args
        */
        private void usage(string[] args){
            if(args.Length < 1 || args.Length > 2){
                Console.WriteLine("Usage: dontnet run <bits> <count>\n\t- bits - the number of bits of the prime number, this must be multiple of 8, and at least 32 bits.\n\t- count - the number of prime numbers to generate, defaults to 1");
                System.Environment.Exit(1);
            }
            this.bits = this.parseInput(args[0]) / 8;
            if(args.Length == 1){
                this.count = 1;
            } else { // 1 <= x <= 2
                this.count = this.parseInput(args[1]);
            }
        }
    }

    public static class Extensions{
        /*
        * Evaluate if probably prime
        */
        public static bool isProbablyPrime(this BigInteger n, int k = 10){
            if(n == 2 || n == 3)
                return true;
            if(n < 2 || n % 2 == 0)
                return false;
            
            BigInteger d = n - 1;
            int s = 0;

            while(d % 2 == 0){
                d /= 2;
                s += 1;
            }

            BigInteger a = getRandomBitIntBelow(n);
            for(int i = 0; i < k; i++){
                BigInteger x = BigInteger.ModPow(a,d,n);
                if (x == 1 || x == n-1)
                    continue;
                for(int r = 1; r < s; r++){
                    x = BigInteger.ModPow(x, 2, n);
                    if(x == 1)
                        continue;
                    if (x == n - 1)
                        break;
                }
                if (x != n - 1)
                    return false;
            }
            return true;
        }

        /*
        * Determine a valid random BigInt below maximum value established (max value = initial random BigInt)
        */
        private static BigInteger getRandomBitIntBelow(BigInteger n){
            Random random = new Random();
            byte[] bytes = n.ToByteArray();
            BigInteger r;

            do{
                random.NextBytes(bytes);
                bytes [bytes.Length - 1] &= (byte)0x7F; // Force sign bit to be positive
                r = new BigInteger(bytes);
            }while (r < 2 || r >= n-2);
            return r;
        }
    }
}