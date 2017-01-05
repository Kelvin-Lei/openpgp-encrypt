package bouncycastle.openpgp;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.NoSuchProviderException;
import java.util.Iterator;

/**
 * Created by kelvinlei on 2017/1/1.
 */
public class Decryptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(Decryptor.class);

    /**
     * Decrypt and verify file
     *
     * @param inputFileName
     * @param keyFileName
     * @param passwd
     * @param pubKeyFileName
     * @param outputFileName
     *
     */
    public static void decryptAndVerifyFile(String inputFileName,
                                            String keyFileName,
                                            char[] passwd,
                                            String pubKeyFileName,
                                            String outputFileName) throws IOException {


        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        InputStream pubKeyIn = new BufferedInputStream(new FileInputStream(pubKeyFileName));
        decryptAndVerifyFile(in, keyIn, passwd, pubKeyIn, outputFileName);

        in.close();
        keyIn.close();
        pubKeyIn.close();

    }


    /**
     * decrypt and verify in message stream
     *
     * @param in
     * @param keyIn
     * @param passwd
     * @param pubKeyIn
     * @param outputFileName
     * @throws IOException
     */
    public static void decryptAndVerifyFile(InputStream in,
                                            InputStream keyIn,
                                            char[] passwd,
                                            InputStream pubKeyIn,
                                            String outputFileName) throws IOException {

        in = PGPUtil.getDecoderStream(in);

        try {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList)o;
            } else {
                enc = (PGPEncryptedDataList)pgpF.nextObject();
            }

            //
            // find the secret key
            //
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {

                pbe = (PGPPublicKeyEncryptedData)it.next();
                sKey = BCPGPUtil.findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(
                    new JcePublicKeyDataDecryptorFactoryBuilder()
                            .setProvider("BC")
                            .build(sKey));

            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
            PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();
            InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedStream);

            Object message = pgpFact.nextObject();

            if (message instanceof PGPOnePassSignatureList) {

                PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)message;
                PGPOnePassSignature ops = p1.get(0);
                PGPLiteralData p2 = (PGPLiteralData)pgpFact.nextObject();
                InputStream dIn = p2.getInputStream();
                int ch;
                PGPPublicKeyRingCollection  pgpRing = new PGPPublicKeyRingCollection(
                        PGPUtil.getDecoderStream(pubKeyIn),
                        new JcaKeyFingerprintCalculator());
                PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());

                ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

                FileOutputStream out = new FileOutputStream(outputFileName);
                while ((ch = dIn.read()) >= 0) {
                    ops.update((byte)ch);
                    out.write(ch);
                }
                out.close();

                PGPSignatureList p3 = (PGPSignatureList)pgpFact.nextObject();

                if (ops.verify(p3.get(0))) {

                    System.out.println("signature verified.");

                } else {

                    System.out.println("signature verification failed.");

                }

            }
            else {

                if (message instanceof PGPLiteralData) {

                    PGPLiteralData ld = (PGPLiteralData)message;

                    String outFileName = outputFileName;

                    InputStream unc = ld.getInputStream();
                    OutputStream fOut =  new BufferedOutputStream(new FileOutputStream(outFileName));

                    Streams.pipeAll(unc, fOut);

                    fOut.close();
                    unc.close();

                } else {

                    throw new PGPException("message is not a simple encrypted file - type unknown.");

                }

            }

            if (pbe.isIntegrityProtected()) {

                if (!pbe.verify()) {
                    System.err.println("message failed integrity check");
                } else {
                    System.err.println("message integrity check passed");
                }

            } else {

                System.err.println("no message integrity check");
            }

        } catch (PGPException e) {
            LOGGER.error("PGP exception.", e);
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            LOGGER.error("No such provider exception.", e);
            throw new RuntimeException(e);
        }

    }
}
