
/**
 * @author Bhavik Makwana
 */

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;

public class AESEncryption {

    byte[] keyBytes;
    Cipher cipher;
    SecretKeySpec key;
    IvParameterSpec ivParameterSpec;
    GCMParameterSpec gcmParameterSpec;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;
    byte[] iv;

    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        BigInteger aa = new BigInteger("6dfc5ff4025d78d5699f530bce1877ff9cc3ac83a8cd3288867c4f4a6d17ba6d", 16);
        AESEncryption aes = new AESEncryption();
        String k = "aesEncryptionKey";
        try {
            aes.createKey(k.getBytes("UTF-8"));
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        String ciddpher = aes.encrypt(aa.toString(16));
        System.out.println(ciddpher);
        System.out.println(aes.decrypt(ciddpher));
    }

    public AESEncryption() {

        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            System.out.println(e.getMessage());
        }
        this.iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);


        ivParameterSpec = new IvParameterSpec(iv);
        gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
    }

    public void createKey(byte[] keyBytes) {
        try {
            this.keyBytes = keyBytes;
            key = new SecretKeySpec(keyBytes, "AES");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String plainText) {
        try {

            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }
    public String decrypt(String cipherText) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public GCMParameterSpec getGcmParameterSpec() {
        return gcmParameterSpec;
    }

    public void setGcmParameterSpec(GCMParameterSpec gcmParameterSpec) {
        this.gcmParameterSpec = gcmParameterSpec;
    }
}