package didisoft;

import com.didisoft.pgp.PGPException;
import com.didisoft.pgp.PGPLib;

import java.io.IOException;

/**
 * Created by kelvinlei on 2016/12/30.
 */
public class SignAndEncrypt {

    public static void signAndEncryptFile(String clearText,
                                   String privateKey,
                                   String privateKeyPwd,
                                   String publicKey,
                                   String cipherText,
                                   boolean asciiArmor,
                                   boolean withIntegrityCheck) {

        PGPLib pgp = new PGPLib();

        try {

            pgp.signAndEncryptFile(clearText,
                    privateKey,
                    privateKeyPwd,
                    publicKey,
                    cipherText,
                    asciiArmor,
                    withIntegrityCheck);

        } catch (PGPException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
