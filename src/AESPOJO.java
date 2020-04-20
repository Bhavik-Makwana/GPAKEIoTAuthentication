import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class AESPOJO {
    private String encryptedString;
    private GCMParameterSpec gcmParameterSpec;

    public AESPOJO(String encryptedString, GCMParameterSpec gcmParameterSpec) {
        this.encryptedString = encryptedString;
        this.gcmParameterSpec = gcmParameterSpec;
    }

    public String getEncryptedString() {
        return encryptedString;
    }

    public void setEncryptedString(String encryptedString) {
        this.encryptedString = encryptedString;
    }

    public GCMParameterSpec getGcmParameterSpec() {
        return gcmParameterSpec;
    }

    public void setGcmParameterSpec(GCMParameterSpec gcmParameterSpec) {
        this.gcmParameterSpec = gcmParameterSpec;
    }
}
