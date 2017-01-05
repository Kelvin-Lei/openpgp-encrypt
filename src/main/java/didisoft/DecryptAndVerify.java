package didisoft;

import com.didisoft.pgp.PGPException;
import com.didisoft.pgp.PGPLib;

import java.io.IOException;

/**
 * Created by kelvinlei on 2016/12/30.
 */
public class DecryptAndVerify {

    public static boolean decryptAndVerifyFile(String cipherText,
                                               String privateKey,
                                               String privateKeyPwd,
                                               String pulbicKey,
                                               String clearText) {

        PGPLib pgp = new PGPLib();
        try {

            boolean validSignature = pgp.decryptAndVerifyFile(cipherText,
                    privateKey,
                    privateKeyPwd,
                    pulbicKey,
                    clearText);
            return validSignature;

        } catch (PGPException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
