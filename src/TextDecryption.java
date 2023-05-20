import java.io.*;
import java.math.BigInteger;

public class TextDecryption {
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
        String downloadPath = System.getProperty("user.home") + File.separator + "Downloads";

        // Lese den privaten Schlüssel aus der Datei sk.txt ein
        BigInteger privateKey = readKeyFromFile(downloadPath + File.separator + "sk.txt");

        // Lese die verschlüsselte Nachricht aus der Datei chiffre.txt ein
        String cipherText = readTextFromFile(downloadPath + File.separator + "chiffre.txt");

        // Entschlüssle die Nachricht gemäß dem ElGamal-Verfahren
        String decryptedText = decryptText(cipherText, privateKey);

        // Speichere den entschlüsselten Text in der Datei text-d.txt
        saveTextToFile(decryptedText, downloadPath + File.separator + "text-d.txt");
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
            System.out.println("Fehler beim Lesen der verschlüsselten Nachricht aus der Datei '" + filePath + "'.");
            e.printStackTrace();
            return null;
        }
    }

    private static String decryptText(String cipherText, BigInteger privateKey) {
        StringBuilder sb = new StringBuilder();
        String[] cipherPairs = cipherText.split("; ");
        for (String pair : cipherPairs) {
            pair = pair.trim().replace("(", "").replace(")", "");
            String[] values = pair.split(", ");
            BigInteger c1 = new BigInteger(values[0]);
            BigInteger c2 = new BigInteger(values[1]);
            BigInteger m = c2.multiply(c1.modPow(privateKey.negate(), n)).mod(n);
            sb.append((char) m.intValue());
        }
        return sb.toString();
    }

    private static void saveTextToFile(String text, String filePath) {
        try {
            FileWriter fileWriter = new FileWriter(filePath);
            fileWriter.write(text);
            fileWriter.close();
            System.out.println("Der entschlüsselte Text wurde erfolgreich in der Datei '" + filePath + "' gespeichert.");
        } catch (IOException e) {
            System.out.println("Fehler beim Speichern des entschlüsselten Texts in der Datei '" + filePath + "'.");
            e.printStackTrace();
        }
    }
}
