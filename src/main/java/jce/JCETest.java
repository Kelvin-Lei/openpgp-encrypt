package jce;

import javax.crypto.Cipher;

/**
 * Created by kelvinlei on 2017/1/3.
 */
public class JCETest {

    public static void main(String[] args) throws Exception {

        System.out.println(Cipher.getMaxAllowedKeyLength("AES"));
    }
}
