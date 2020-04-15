package JPAKE;

import org.bouncycastle.crypto.agreement.jpake.JPAKERound1Payload;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentHashMap;

public class RoundOne {
    private ConcurrentHashMap<Long, JPAKERound1Payload> jpakeRoundOne = new ConcurrentHashMap<>();

    public ConcurrentHashMap<Long, JPAKERound1Payload> getJpakeRoundOne() {
        return jpakeRoundOne;
    }

    public void setJpakeRoundOne(ConcurrentHashMap<Long, JPAKERound1Payload> jpakeRoundOne) {
        this.jpakeRoundOne = jpakeRoundOne;
    }
}
