/**
 * Copyright (c) 2017-2019 The Elastos Developers
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package org.elastos.crypto;

import org.junit.Assert;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.Base64;

/**
 * clark
 * <p>
 * 3/7/19
 */
public class PrivateKeyTest {

    private static final String goodPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXQIBAAKBgQCjFca3HtjM6T6HQEApX7bDuatpiXiEMKr1uiTbAgOvzQpBa7cy\n" +
            "Y0Xr/cEw4ovwjjVHXfr5uRqY/J+w1p6RVVtxy96hdR25ySj0636Tl+swTxT/+BKi\n" +
            "OOkzEHUL3vxrfkqYZHXg/tYUET3yQsjrtAWU1Cw6ZU0JI8jUKIeQQy7jrQIDAQAB\n" +
            "AoGAKlQSmaDmAHlhg1VH0fVHyJE+Tkwh/Z1sIg9IVZe2QUDksoo0qF1f3pqkM/34\n" +
            "+FzQs09PPtWuc5rOD+YEjhArhXi2nH5QFyS4nYe6hrVHmCDhsZK3sXe6x9az0AgY\n" +
            "GNqFYxD2bdrMp5YeKC1pDtjT958/1WPKJATceQ5FTqsXrwECQQDpSaJ+t1HlWm6q\n" +
            "yBjEbX44ZaGK4lQByK2bUaaEpi9EMk5705SUFvZD4FnHtP5ZKrmpI5vusR5wmbxt\n" +
            "zUkR/vWhAkEAsvZw/00CeJB0XkUlnbpbH2qsh5juHWr+vO6POSovTgR1hK3+vZqh\n" +
            "JY/yyX/sAIr2z8dh/4pufhSLuS/lAAdajQJACS/6M01a71Jpa1ZoC0xYnTX7b7HM\n" +
            "JynVFHnZuf2lfOUSTDQf9NkWp8OtJX1OSwqwtyWM3ZCiJ0MWtahRCWFmIQJBAIOn\n" +
            "4yceK0Qw2TsE2ZB4qVKqcnRq4DnKHc82HS1ryFM32pCaRD6ORCDTDkSIlEEt+jaP\n" +
            "MpwA5hpg2Q2Km4hy4H0CQQDGQEUid5GgYYpE5XNe0ocONeOZHcAyFaWK0OBzvx+U\n" +
            "kA0JPmGuqyj2KciYii0dI4UIUGYNeusaGnZKxoZfGuFo\n" +
            "-----END RSA PRIVATE KEY-----\n";
    private static final String badPrivateKey  = "IAMNOTAKEY";
    private static final String badPrivateKey2 = "-----BEGIN PRIVATE KEY-----MIIEpAIBAAKCAQE-----END PRIVATE KEY-----";
    private static final String badPrivateKey3 = "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQE-----END RSA PRIVATE KEY-----";

    @Test
    public void TestGoodPrivKey() throws Exception{

        PrivateKey privateKey = new PrivateKey(goodPrivateKey.getBytes());

        Assert.assertFalse("Private key is blank ", privateKey.isEmpty());

        PublicKey pub = privateKey.publicKey();
        String message = "hello,world";
        byte[] signed = privateKey.signBytes(message.getBytes());
        Signature signature = new Signature(signed);
        System.out.println(signature.string());
        Assert.assertTrue(signature.VerifySignature(pub,message));

    }


}
