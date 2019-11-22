package net.petrikainulainen.junit5;

import org.junit.jupiter.api.Test;
import org.junit.Assert;
class JUnit5ExampleTest {

    @Test
    void justAnExample() {
        System.out.println("This test method should be run");
        Assert.assertEquals(3.0, 1.2);
    }
}