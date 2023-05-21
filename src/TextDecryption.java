import java.io.*;
import java.math.BigInteger;

public class TextDecryption {

    //prepare n
    private static final BigInteger n = new BigInteger(TextEncryption.removeSpaces(
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

    public static void main(String[] args) {

        //create path
        String dlPath = System.getProperty("user.home") + File.separator + "Downloads";

        //read private key from file sk.txt
        BigInteger privateKey = readKeyFromFile(dlPath + File.separator + "sk.txt");

        //read encrypted text from chiffre.txt
        String text = readTextFromFile(dlPath + File.separator + "chiffre.txt");

        //decrypt text
        String decryptedText = decryptText(text, privateKey);

        //save decrypted text to text-d.txt
        saveTextToFile(decryptedText, dlPath + File.separator + "text-d.txt");
    }

    //method to read private key
    private static BigInteger readKeyFromFile(String filePath) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filePath));
            String key = reader.readLine();
            reader.close();
            return new BigInteger(key);
        } catch (IOException e) {
            System.out.println("error");
            e.printStackTrace();
            return null;
        }
    }

    //method to read text from file
    private static String readTextFromFile(String filePath) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filePath));
            StringBuilder strBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                strBuilder.append(line);
            }
            reader.close();
            return strBuilder.toString();
        } catch (IOException e) {
            System.out.println("error");
            e.printStackTrace();
            return null;
        }
    }

    //method to decrypt the encrypted text
    private static String decryptText(String cipherText, BigInteger privateKey) {
        StringBuilder strBuilder = new StringBuilder();
        String[] pairs = cipherText.split(";");
        for (String pair : pairs) {
            pair = pair.trim().replace("(", "").replace(")", "");
            String[] values = pair.split(",");
            BigInteger chr1 = new BigInteger(values[0]);
            BigInteger chr2 = new BigInteger(values[1]);
            BigInteger m = chr2.multiply(chr1.modPow(privateKey.negate(), n)).mod(n);
            strBuilder.append((char) m.intValue());
        }
        return strBuilder.toString();
    }


    //method to save text to file
    private static void saveTextToFile(String text, String filePath) {
        try {
            FileWriter fileWriter = new FileWriter(filePath);
            fileWriter.write(text);
            fileWriter.close();
            System.out.println("Saved to '" + filePath);
        } catch (IOException e) {
            System.out.println("error");
            e.printStackTrace();
        }
    }
}
