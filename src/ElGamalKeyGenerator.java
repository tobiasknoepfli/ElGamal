import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.concurrent.ThreadLocalRandom;

public class ElGamalKeyGenerator {

    //prepare and create n
    private static final BigInteger n = new BigInteger(removeSpaces(
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 " +
                    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD " +
                    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 " +
                    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED " +
                    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D " +
                    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F " +
                    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D " +
                    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B " +
                    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 " +
                    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 " +
                    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"), 16);


    private static String removeSpaces(String input) {
        return input.replaceAll("\\s+", "");
    }

    //create g
    private static final BigInteger g = BigInteger.valueOf(2);

    //generate the keys
    public static void main(String[] args) {
        generateElGamalKeys();
    }

    //method to generate the keys
    public static void generateElGamalKeys() {
        // generate a random BigInteger beween 1 and n-1 --> private key
        BigInteger privateKey = generateRandomNumberInRange(BigInteger.ONE, n.subtract(BigInteger.ONE));

        // calculate the third part of the public key
        BigInteger publicKey = g.modPow(privateKey, n);

        // save the private key to the file "sk.txt" in the user's download folder
        saveKeyToFile(privateKey, "sk.txt", getDownloadFolderPath());

        // save the public key to the file "pk.txt" in the user's download folder
        saveKeyToFile(publicKey, "pk.txt", getDownloadFolderPath());
    }

    //method to generate a random number with BigInteger
    private static BigInteger generateRandomNumberInRange(BigInteger min, BigInteger max) {
        SecureRandom rnd = new SecureRandom();
        int bits = max.bitLength();
        BigInteger randomNumber;
        do {
            randomNumber = new BigInteger(bits, rnd);
        } while (randomNumber.compareTo(min) < 0 || randomNumber.compareTo(max) > 0);
        return randomNumber;
    }

    //method to save a key to a file
    private static void saveKeyToFile(BigInteger key, String fileName, String folderPath) {
        try {
            // convert to decimal
            String keyString = key.toString();

            //save the key in a file
            FileWriter fileWriter = new FileWriter(folderPath + "/" + fileName);
            fileWriter.write(keyString);
            fileWriter.close();

            System.out.println("saved at " + fileName);
        } catch (IOException e) {
            System.out.println("error");
            e.printStackTrace();
        }
    }

    //method to get download folder path
    private static String getDownloadFolderPath() {
        String userHome = System.getProperty("user.home");
        return userHome + "/Downloads";
    }
}
