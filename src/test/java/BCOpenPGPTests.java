import bouncycastle.openpgp.Decryptor;
import bouncycastle.openpgp.Encryptor;
import org.junit.Test;

import java.io.IOException;

/**
 * Created by kelvinlei on 2017/1/1.
 */
public class BCOpenPGPTests {

    @Test
    public void testEncryptFile() {

        boolean asciiArmor = true;
        boolean withIntegrityCheck = true;
        String clearText = "src/test/resources/HK1470742659229.xml";
        String OrgAPrivateKey = "src/test/resources/keys/organizationA_sec.asc";
        String OrgAKeyPwd = "organizationA";
        String OrgBPublicKey = "src/test/resources/keys/organizationB_pub.asc";
        String cipherText = "src/test/resources/HK1470742659229.xml.pgp";


        Encryptor.signAndEncryptFile(cipherText,
                clearText,
                OrgBPublicKey,
                OrgAPrivateKey,
                OrgAKeyPwd,
                asciiArmor,
                withIntegrityCheck);

    }

    @Test
    public void testDecryptFile() throws IOException {

        String OrgBKeyPwd = "organizationB";

        String cipherText = "src/test/resources/HK1470742659229.xml.pgp";
        String OrgBPrivateKey = "src/test/resources/keys/organizationB_sec.asc";
        String OrgAPublicKey = "src/test/resources/keys/organizationA_pub.asc";
        String decText = "src/test/resources/HK1470742659229.dec.xml";

        Decryptor.decryptAndVerifyFile(cipherText,
                OrgBPrivateKey,
                OrgBKeyPwd.toCharArray(),
                OrgAPublicKey,
                decText);
    }
}
