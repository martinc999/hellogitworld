package pl.payu.coordinator.main.security.crypto;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.payu.coordinator.main.exception.BusinessException;

public final class Crypto {

    private static final Logger LOGGER = LoggerFactory.getLogger(Crypto.class);

    public static final String ALGORITHM = "DH";

    public static final String HMAC_ALGORITHM_SHA1 = "HmacSHA1";
    public static final String HMAC_ALGORITHM_SHA256 = "HmacSHA256";

    public static final String ALGORITHM_SHA1 = "SHA-1";
    public static final String ALGORITHM_SHA256 = "SHA-256";
    public static final String ALGORITHM_MD5 = "MD5";

    public static final int HMAC_SHA1_KEYSIZE = 160;
    public static final int HMAC_SHA256_KEYSIZE = 256;

    public static final String CHARSET_UTF8 = "UTF-8";

    public static final String DEFAULT_MODULUS_HEX = "DCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E"
            + "F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557"
            + "7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382"
            + "6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB";

    public static final String DEFAULT_MODULUS_BASE64 = "ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOc"
            + "Pym2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXj"
            + "gmY0rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr";

    public static final long DEFAULT_GENERATOR = 2;
    public static final String DEFAULT_GENERATOR_BASE64 = "Ag==";

    private Crypto() {
        // hidden default constructor of utility class
    }

    public static SecretKey generateMacSha1Key() {
        return generateMacKey(HMAC_ALGORITHM_SHA1, HMAC_SHA1_KEYSIZE);
    }

    public static SecretKey generateMacSha256Key() {
        return generateMacKey(HMAC_ALGORITHM_SHA256, HMAC_SHA256_KEYSIZE);
    }

    protected static SecretKey generateMacKey(String algorithm, int keySize) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(keySize);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Unsupported algorithm [algorithm={},keySize={},error={}]", new Object[] { algorithm, keySize,
                    e });
            return null;
        }
    }

    public static KeyPair generateKeyPair(DHParameterSpec dhSpec) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhSpec);
            return keyGen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            LOGGER.error("error while generating key pair with [g={},p={}]", dhSpec.getG(), dhSpec.getP());
            return null;
        }
    }

    public static String hexEncode(byte[] aInput) {
        StringBuilder result = new StringBuilder();
        char[] digits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        for (int idx = 0; idx < aInput.length; ++idx) {
            byte b = aInput[idx];
            result.append(digits[(b & 0xf0) >> 4]);
            result.append(digits[b & 0x0f]);
        }
        return result.toString();
    }

    public static String publicKeyToString(DHPublicKey publicKey) {
        return new String(Base64.encodeBase64(publicKey.getY().toByteArray()));
    }

    public static DHParameterSpec generateRandomParameter(int primeSize, int keySize) {
        try {
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");

            DHGenParameterSpec genParameterSpec = new DHGenParameterSpec(primeSize, keySize);

            paramGen.init(genParameterSpec);

            AlgorithmParameters params = paramGen.generateParameters();

            DHParameterSpec result = params.getParameterSpec(DHParameterSpec.class);

            LOGGER.info("Generated random DHParameterSpec [g={},p={}]", result.getG(), result.getP());

            return result;
        } catch (GeneralSecurityException e) {
            LOGGER.error("Cannot generate DH for specified params [primeSize={},keySize={},error={}]", new Object[] {
                    primeSize, keySize, e });
            return null;
        }
    }

    public static String generateRandomHash32() {
        return RandomStringUtils.randomAlphanumeric(32);
    }

    public static byte[] sign(Key key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        String algorithm = key.getAlgorithm();
        Mac mac = Mac.getInstance(algorithm);

        mac.init(key);

        return mac.doFinal(data);
    }

    public static String encryptMacKey(String algorithm, KeyPair kp, DHParameterSpec dh, byte[] macKey,
            String consumerPublicKeyBase64) {

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("MAC key encryption algorithm error", e);
        }

        if (digest == null) {
            return null;
        }

        byte[] hzz = getDigestedZZ(digest, kp, dh, consumerPublicKeyBase64);

        if (hzz.length != macKey.length) {
            LOGGER.error("MAC key legth different from shared secret digest length!");
        }

        byte[] encMacKey = new byte[hzz.length];

        for (int i = 0; i < hzz.length; i++) {
            byte b1 = hzz[i];
            byte b2 = macKey[i];
            encMacKey[i] = (byte) (b1 ^ b2);
        }

        String encMacKeyBase64 = new String(Base64.encodeBase64(encMacKey));

        LOGGER.debug("MAC key successfully encrypted [base64={}]", encMacKeyBase64);

        return encMacKeyBase64;
    }

    public static String generateSHA256Hash(String valueToHash) throws BusinessException {
        return generateHash(valueToHash, ALGORITHM_SHA256);
    }

    public static String generateMD5Hash(String valueToHash) throws BusinessException {
        return generateHash(valueToHash, ALGORITHM_MD5);
    }

    private static byte[] generateDigest(String valueToHash, String algorithm) throws BusinessException {
        return generateDigest(valueToHash, algorithm, CHARSET_UTF8);
    }

    public static String generateHash(String valueToHash, String algorithm) throws BusinessException {
        return asHex(generateDigest(valueToHash, algorithm));
    }

    private static byte[] generateDigest(String valueToHash, String algorithm, String charset) throws BusinessException {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("Algorithm does not exists! Given string: " + algorithm, e);
            throw new BusinessException("checkout.errors.package.GENERIC_ERROR_CODE", e);
        }

        try {
            digest.update(valueToHash.getBytes(charset));
        } catch (UnsupportedEncodingException e) {
            LOGGER.warn("Unknown charset name: " + charset, e);
            throw new BusinessException("checkout.errors.package.GENERIC_ERROR_CODE", e);
        }

        return digest.digest();
    }

    private static String asHex(byte[] mdbytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mdbytes.length; i++) {
            sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

    protected static byte[] getDigestedZZ(MessageDigest digest, KeyPair kp, DHParameterSpec dh,
            String otherPublicKeyBase64) {
        DHPublicKey dhPublicKey = stringToPublicKey(dh, otherPublicKeyBase64);
        DHPrivateKey dhPrivateKey = (DHPrivateKey) kp.getPrivate();
        BigInteger xa = dhPrivateKey.getX();
        BigInteger yb = dhPublicKey.getY();
        BigInteger p = dh.getP();

        BigInteger zz = yb.modPow(xa, p);

        return digest.digest(zz.toByteArray());
    }

    protected static DHPublicKey stringToPublicKey(DHParameterSpec dh, String publicKeyBase64) {
        try {
            byte[] yBinary = Base64.decodeBase64(publicKeyBase64.getBytes());
            BigInteger y = new BigInteger(yBinary);

            DHPublicKeySpec dhPublicKeySpec = new DHPublicKeySpec(y, dh.getP(), dh.getG());

            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

            return (DHPublicKey) keyFactory.generatePublic(dhPublicKeySpec);
        } catch (GeneralSecurityException e) {
            LOGGER.warn("Cannot create PublicKey object [publicKeyBase64={},error={}]", publicKeyBase64, e);
            return null;
        }
    }
}
