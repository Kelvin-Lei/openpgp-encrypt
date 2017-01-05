import didisoft.DecryptAndVerify;
import didisoft.SignAndEncrypt;
import org.junit.Test;

/**
 * Created by kelvinlei on 2016/12/31.
 */
public class DidiTests {

    @Test
    public void testSignAndEncrypt() {

        boolean asciiArmor = true;

        boolean withIntegrityCheck = true;

        String clearText = "src/test/resources/HK1470742659229.xml";
        String OrgAPrivateKey = "src/test/resources/keys/organizationA_sec.asc";
        String OrgAKeyPwd = "organizationA";
        String OrgBPublicKey = "src/test/resources/keys/organizationB_pub.asc";
        String cipherText = "src/test/resources/HK1470742659229.xml.pgp";

        SignAndEncrypt.signAndEncryptFile(clearText,
                OrgAPrivateKey,
                OrgAKeyPwd,
                OrgBPublicKey,
                cipherText,
                asciiArmor,
                withIntegrityCheck);

        System.out.println("Sign and Encrypt file Succeed.");
    }

    @Test
    public void testDecryptAndVerify() {

        String HSBCKeyPwd = "organizationB";

        String cipherText = "src/test/resources/HK1470742659229.xml.pgp";
        String HSBCPrivateKey = "src/test/resources/keys/organizationB_sec.asc";
        String TencentPublicKey = "src/test/resources/keys/organizationA_pub.asc";
        String decText = "src/test/resources/HK1470742659229.dec.xml";

        boolean validSignature = DecryptAndVerify.decryptAndVerifyFile(cipherText,
                                                                        HSBCPrivateKey,
                                                                        HSBCKeyPwd,
                                                                        TencentPublicKey,
                                                                        decText);

        if (validSignature) {
            System.out.println("Valid Succeed. Signature is valid.");
        } else {
            System.out.println("Valid Failed. Signature is invalid.");
        }
    }


}
