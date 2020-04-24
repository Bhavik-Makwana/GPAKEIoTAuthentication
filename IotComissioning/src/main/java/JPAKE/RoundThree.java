/**
 * @author Bhavik Makwana
 */
package JPAKE;

import org.bouncycastle.crypto.agreement.jpake.JPAKERound3Payload;

import java.util.concurrent.ConcurrentHashMap;

public class RoundThree {
    private ConcurrentHashMap<Long, JPAKERound3Payload> jpakeRoundThree = new ConcurrentHashMap<>();

    public ConcurrentHashMap<Long, JPAKERound3Payload> getJpakeRoundThree() {
        return jpakeRoundThree;
    }

    public void setJpakeRoundThree(ConcurrentHashMap<Long, JPAKERound3Payload> jpakeRoundThree) {
        this.jpakeRoundThree = jpakeRoundThree;
    }
}
