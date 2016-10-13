package pl.com.mds.pse.data.encryption.encryptor;

/**
 * @author trutyna
 */
public class EncryptorTest {

    /*@Test*/
    public void shouldEncryptAndDecrypt() throws Exception {

        String plainText = "Hello world!";
        //String cipherText = Encryptor.encode(plainText);
        String decryptedCipherText = Encryptor.decode("jfH+0YmWNoqDunso9zi9tQ==");

        System.out.println(plainText);
        //System.out.println(cipherText);
        System.out.println(decryptedCipherText);
    }
}
