import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class TextEncryption {
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

    public static String removeSpaces(String input) {
        return input.replaceAll("\\s+", "");
    }

    private static final BigInteger g = new BigInteger("2");

    public static void main(String[] args) {
        String downloadPath = System.getProperty("user.home") + File.separator + "Downloads";

        // Lese den öffentlichen Schlüssel aus der Datei pk.txt ein
        BigInteger publicKey = readKeyFromFile(downloadPath + File.separator + "pk.txt");

        // Lese den Text aus der Datei text.txt ein
        String plainText = readTextFromFile(downloadPath + File.separator + "text.txt");

        // Verschlüssele den Text gemäß dem ElGamal-Verfahren
        String cipherText = encryptText(plainText, publicKey);

        // Speichere die verschlüsselten Texte in der Datei chiffre.txt
        saveTextToFile(cipherText, downloadPath + File.separator + "chiffre.txt");
    }

    private static BigInteger readKeyFromFile(String filePath) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filePath));
            String keyString = reader.readLine();
            reader.close();
            return new BigInteger(keyString);
        } catch (IOException e) {
            System.out.println("Fehler beim Lesen des Schlüssels aus der Datei '" + filePath + "'.");
            e.printStackTrace();
            return null;
        }
    }

    private static String readTextFromFile(String filePath) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filePath));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            reader.close();
            return sb.toString();
        } catch (IOException e) {
            System.out.println("Fehler beim Lesen des Texts aus der Datei '" + filePath + "'.");
            e.printStackTrace();
            return null;
        }
    }

    private static String encryptText(String plainText, BigInteger publicKey) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < plainText.length(); i++) {
            char c = plainText.charAt(i);
            int asciiCode = (int) c;

            // Verschlüssle den ASCII-Code gemäß dem ElGamal-Verfahren
            BigInteger message = new BigInteger(Integer.toString(asciiCode));
            BigInteger r = generateRandomNumberInRange(BigInteger.ONE, n.subtract(BigInteger.ONE));
            BigInteger c1 = g.modPow(r, n);
            BigInteger c2 = publicKey.modPow(r, n).multiply(message).mod(n);

            // Füge die verschlüsselten Werte dem Ergebnisstring hinzu
            sb.append("(").append(c1).append(",").append(c2).append("); ");
        }
        return sb.toString();
    }

    private static void saveTextToFile(String text, String filePath) {
        try {
            FileWriter fileWriter = new FileWriter(filePath);
            fileWriter.write(text);
            fileWriter.close();
            System.out.println("Die Verschlüsselung wurde erfolgreich in der Datei '" + filePath + "' gespeichert.");
        } catch (IOException e) {
            System.out.println("Fehler beim Speichern der Verschlüsselung in der Datei '" + filePath + "'.");
            e.printStackTrace();
        }
    }

    private static BigInteger generateRandomNumberInRange(BigInteger min, BigInteger max) {
        BigInteger range = max.subtract(min).add(BigInteger.ONE);
        BigInteger randomNumber;
        do {
            SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[range.bitLength() / 8];
            random.nextBytes(bytes);
            randomNumber = new BigInteger(1, bytes);
        } while (randomNumber.compareTo(range) >= 0);
        return randomNumber.add(min);
    }
}
