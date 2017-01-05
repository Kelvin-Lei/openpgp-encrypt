package bouncycastle.openpgp;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Iterator;

/**
 * Created by kelvinlei on 2017/1/1.
 */
public class Encryptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(Encryptor.class);

    /**
     * Sign and encrypt file with keys located in files
     *
     * @param outputFileName
     * @param inputFileName
     * @param encKeyFileName
     * @param signKeyFileName
     * @param signKeyPwd
     * @param armor
     * @param withIntegrityCheck
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    public static void signAndEncryptFile(String outputFileName,
                                          String inputFileName,
                                          String encKeyFileName,
                                          String signKeyFileName,
                                          String signKeyPwd,
                                          boolean armor,
                                          boolean withIntegrityCheck) {

        InputStream signKeyIn = null;
        OutputStream out = null;
        try {

            signKeyIn = new FileInputStream(signKeyFileName);
            out = new BufferedOutputStream(new FileOutputStream(outputFileName));

            signAndEncryptFile(out,
                                inputFileName,
                                encKeyFileName,
                                signKeyIn,
                                signKeyPwd.toCharArray(),
                                armor,
                                withIntegrityCheck);

        } catch (IOException e) {

            LOGGER.error("Sign and encrypt file i/o error.", e);
            throw new RuntimeException(e);

        } finally {

            if (signKeyIn != null) {
                try {
                    signKeyIn.close();
                } catch (IOException e) {
                    LOGGER.error("Sign key file[" + inputFileName + "] close error.", e);
                }
            }
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    LOGGER.error("Encrypted output file[" + inputFileName + "] close error.", e);
                }
            }

        }
    }

    /**
     *
     *
     * @param out
     * @param fileName
     * @param encKeyFileName
     * @param signKeyIn
     * @param pass
     * @param armor
     * @param withIntegrityCheck
     * @throws IOException
     * @throws NoSuchProviderException
     */
    private static void signAndEncryptFile(OutputStream out,
                                          String fileName,
                                          String encKeyFileName,
                                          InputStream signKeyIn,
                                          char[] pass,
                                          boolean armor,
                                          boolean withIntegrityCheck) throws IOException {

        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        OutputStream literalDataOutStream = null;
        FileInputStream inputFileStream = null;
        PGPLiteralDataGenerator lg = null;
        PGPCompressedDataGenerator comData = null;
        BCPGOutputStream bOut = null;
        OutputStream cOut = null;
        PGPEncryptedDataGenerator cPk = null;
        try {

            PGPSecretKey  pgpSec = BCPGPUtil.readSecretKey(signKeyIn);
            PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));

            PGPSignatureGenerator sGen = new PGPSignatureGenerator(
                    new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA256)
                            .setProvider("BC"));

            sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
            Iterator it = pgpSec.getPublicKey().getUserIDs();
            if (it.hasNext()) {
                PGPSignatureSubpacketGenerator  spGen = new PGPSignatureSubpacketGenerator();
                spGen.setSignerUserID(false, (String)it.next());
                sGen.setHashedSubpackets(spGen.generate());
            }

            cPk = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                            .setWithIntegrityPacket(withIntegrityCheck)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC"));

            PGPPublicKey encKey = BCPGPUtil.readPublicKey(encKeyFileName);
            cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

            cOut = cPk.open(out, new byte[1 << 16]);

            comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

            bOut = new BCPGOutputStream(comData.open(cOut));

            sGen.generateOnePassVersion(false).encode(bOut);

            lg = new PGPLiteralDataGenerator();

            File inputFile = new File(fileName);
            literalDataOutStream = lg.open(bOut, PGPLiteralData.BINARY, inputFile);

            inputFileStream = new FileInputStream(inputFile);
            byte[] bytes = IOUtils.toByteArray(inputFileStream);

            literalDataOutStream.write(bytes);
            sGen.update(bytes);
            sGen.generate().encode(bOut);

        } catch (PGPException e) {

            if (e.getUnderlyingException() != null) {
                LOGGER.error("pgp exception.", e.getUnderlyingException().getStackTrace());
            } else {
                LOGGER.error("pgp exception.", e);
            }
            throw new RuntimeException(e);

        } finally {

            if (literalDataOutStream != null) {
                literalDataOutStream.close();
            }
            if (inputFileStream != null) {
                inputFileStream.close();
            }
            if (lg != null) {
                lg.close();
            }
            if (comData != null) {
                comData.close();
            }
            if (bOut != null) {
                bOut.close();
            }
            if (cOut != null) {
                cOut.close();
            }
            if (cPk != null) {
                cPk.close();
            }
            if (armor)
            {
                out.close();
            }
        }

    }
}
