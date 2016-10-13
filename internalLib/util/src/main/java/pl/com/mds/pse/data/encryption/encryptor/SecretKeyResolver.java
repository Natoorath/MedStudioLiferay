package pl.com.mds.pse.data.encryption.encryptor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.PropsUtil;
import com.liferay.portal.kernel.util.Validator;

public class SecretKeyResolver {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    private static final String KEYSTORE_DEFAULT_ALIAS = "PSESecretKey";
    private static final String KEYSTORE_DEFAULT_PASS = "Qwas.100";
    private static final String KEYSTORE_DEFAULT_PATH = "defaultKeyStore";

    private static final String SHOULD_ENCRYPT_KEY = "szyfrowanieDanychOsobowych.wlaczone";
    private static final String KEYSTORE_ALIAS_KEY = "szyfrowanieDanychOsobowych.nazwaKlucza";
    private static final String KEYSTORE_PATH_KEY = "szyfrowanieDanychOsobowych.sciezkaKlucza";
    private static final String KEYSTORE_PASS_KEY = "szyfrowanieDanychOsobowych.hasloKlucza";
    private static final String KEYSTORE_LOG_ERROR_KEY = "szyfrowanieDanychOsobowych.pelnyLog";

    private static final String KEYSTORE_ALIAS;
    private static final String KEYSTORE_PATH;
    private static final String KEYSTORE_PASS;
    private static final Boolean KEYSTORE_LOG;

    private static Boolean SHOULD_ENCRYPT;
    static SecretKey SECRET_KEY = null;
    
    private static Log log = LogFactoryUtil.getLog(SecretKeyResolver.class);

    static {
	String keystoreAlias = PropsUtil.get(KEYSTORE_ALIAS_KEY);
	String keystorePath = PropsUtil.get(KEYSTORE_PATH_KEY);
	String keystorePass = PropsUtil.get(KEYSTORE_PASS_KEY);
	String keystoreLogError = PropsUtil.get(KEYSTORE_LOG_ERROR_KEY);
	String shouldEncrypt = PropsUtil.get(SHOULD_ENCRYPT_KEY);
	
	KEYSTORE_ALIAS = Validator.isNotNull(keystoreAlias) ? keystoreAlias : KEYSTORE_DEFAULT_ALIAS;
        KEYSTORE_PATH = Validator.isNotNull(keystorePath) ? keystorePath : KEYSTORE_DEFAULT_PATH;
        KEYSTORE_PASS = Validator.isNotNull(keystorePass) ? keystorePass : KEYSTORE_DEFAULT_PASS;
        KEYSTORE_LOG = Validator.isNotNull(keystoreLogError) ? Boolean.parseBoolean(keystoreLogError) : true; 

        SHOULD_ENCRYPT = Validator.isNotNull(shouldEncrypt) ? Boolean.parseBoolean(shouldEncrypt) : true;

        if (SHOULD_ENCRYPT) {
            SECRET_KEY = resolveSecretKey();
        }

        SHOULD_ENCRYPT = SHOULD_ENCRYPT && SECRET_KEY != null;
    }

    private static SecretKey resolveSecretKey() {
		
        try {
            File file = new File(KEYSTORE_PATH);

            KeyStore keyStore = KeyStore.getInstance("JCEKS");

            KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(KEYSTORE_PASS.toCharArray());

            if (file.exists()) {
        	try (FileInputStream fis = new FileInputStream(file)) {
        	    keyStore.load(fis, KEYSTORE_PASS.toCharArray());
        	}
            } else {
        	ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        	URL resource = classLoader.getResource(KEYSTORE_DEFAULT_PATH);
        	File defaultfile = new File(resource.toURI());
        	
        	KeyStore defaultKeyStore = KeyStore.getInstance("JCEKS");
        	KeyStore.PasswordProtection defaultKeyPassword = new KeyStore.PasswordProtection(KEYSTORE_DEFAULT_PASS.toCharArray());
        	try (FileInputStream fis = new FileInputStream(defaultfile)) {
        	    defaultKeyStore.load(fis, KEYSTORE_DEFAULT_PASS.toCharArray());
        	}
        	KeyStore.SecretKeyEntry defaultEntry = (KeyStore.SecretKeyEntry) defaultKeyStore.getEntry(KEYSTORE_DEFAULT_ALIAS, defaultKeyPassword);

        	keyStore.load(null, null);        	
        	file.getParentFile().mkdirs();
        	try (FileOutputStream fos = new FileOutputStream(file)) {
        	    keyStore.setEntry(KEYSTORE_ALIAS, defaultEntry, keyPassword);
        	    keyStore.store(fos, KEYSTORE_PASS.toCharArray());
        	}
            }

            KeyStore.Entry entry = keyStore.getEntry(KEYSTORE_ALIAS, keyPassword);

            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        } catch (Throwable ex) {
            log.error("Blad podczas szyfrowania danych " + ex.getMessage());

            if (KEYSTORE_LOG) {
        	log.error(ex);
            }
            return null;
        }
    }

    private static String firstNotNull(String props, String defaultValue) {
        return props != null ? props : defaultValue;
    }

    public static boolean shouldEncrypt() {
        return SHOULD_ENCRYPT;
    }
}
