import javax.crypto.spec.IvParameterSpec;

public class AESPOJO {
    private String encryptedString;
    private IvParameterSpec ivParameterSpec;

    public AESPOJO(String encryptedString, IvParameterSpec ivParameterSpec) {
        this.encryptedString = encryptedString;
        this.ivParameterSpec = ivParameterSpec;
    }

    public String getEncryptedString() {
        return encryptedString;
    }

    public void setEncryptedString(String encryptedString) {
        this.encryptedString = encryptedString;
    }

    public IvParameterSpec getIvParameterSpec() {
        return ivParameterSpec;
    }

    public void setIvParameterSpec(IvParameterSpec ivParameterSpec) {
        this.ivParameterSpec = ivParameterSpec;
    }
}
