package pl.com.mds.pse.data.encryption.encryptor;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class Encryptor {

    public static String encode(String plainText) {
        if (SecretKeyResolver.shouldEncrypt()) {
            try {



                Cipher cipher = getCipher(Cipher.ENCRYPT_MODE);
                byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

                String s = Base64.encodeBase64String(encryptedBytes);



                return s;
            } catch (Throwable ex) {
                System.out.println("Blad odszyfrowania danych dla " + plainText + " : " + ex.getMessage());
            }
        }
        return plainText;
    }

    private static boolean shouldEncode(String plainText) {
        if (plainText == null) {
            return false;
        }
        String decoded = decode(plainText, false);

        return decoded.equals(plainText);
    }

    public static String decode(String encrypted, boolean logError) {
        if (SecretKeyResolver.shouldEncrypt()) {
            try {
                Cipher cipher = getCipher(Cipher.DECRYPT_MODE);
                byte[] plainBytes = cipher.doFinal(Base64.decodeBase64(encrypted));

                String s = new String(plainBytes);

                return s;
            } catch (Throwable ex) {
                if (logError) {
                    System.out.println("Blad odszyfrowania danych dla " + encrypted + " : " + ex.getMessage());
                }
            }
        }
        return encrypted;
    }

    public static String decode(String encrypted) {

        return decode(encrypted, true);
    }

    private static Cipher getCipher(int cipherMode) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(cipherMode, SecretKeyResolver.SECRET_KEY, new IvParameterSpec(new byte[16]));

        return cipher;
    }
}