package JPAKE;

import org.bouncycastle.crypto.agreement.jpake.JPAKERound2Payload;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentHashMap;

public class RoundTwo {
    private ConcurrentHashMap<Long, JPAKERound2Payload> jpakeRoundTwo = new ConcurrentHashMap<>();

    public ConcurrentHashMap<Long, JPAKERound2Payload> getJpakeRoundTwo() {
        return jpakeRoundTwo;
    }

    public void setJpakeRoundTwo(ConcurrentHashMap<Long, JPAKERound2Payload> jpakeRoundTwo) {
        this.jpakeRoundTwo = jpakeRoundTwo;
    }
}
