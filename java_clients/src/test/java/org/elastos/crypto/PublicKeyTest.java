/**
 * Copyright (c) 2017-2019 The Elastos Developers
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package org.elastos.crypto;

import org.junit.Assert;
import org.junit.Test;
import sun.security.rsa.RSAPublicKeyImpl;

import java.security.interfaces.RSAPublicKey;

/**
 * clark
 * <p>
 * 3/5/19
 */
public class PublicKeyTest {

    private static final String goodPublicKey    = "-----BEGIN PUBLIC KEY-----\n" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA31GRu9r2QRA9PtIzMKyV\n" +
            "3vloQlrmxRLYIgiUsNg6bNOmTOJ1og+HNpTY8XOujf3KpPS38F1XM3AAJQi3pUjc\n" +
            "JEdeiqroFf8b7t2pas1V+Bg2XAWWbfKctpnMuxeIYuJE52KhUK4y+qGaLXI+53oT\n" +
            "09w3V4CdeQNZllVL2a6q+6gjpdZ+/YOPQ+dncHtYCxNHu1Idub0EP/ZMkdcHLwpi\n" +
            "/gmuw7qvdpQTeiw54krV3MoiZq50ZTxTFRCjFJ+C+pmrYaPygrkCkv3sj3v1Be8k\n" +
            "0EBYsMH8yZoigbyE0/SlCH+RGLSiS1yAV+MHcoVMzPFbXnFv9usI3UNVSXrDSzsx\n" +
            "YgiDaeX7KVrraKhJrM/LIypZbJDiKLpLzKFEx+SkSQ/3e8eSsedp7N5RSvcz9GU6\n" +
            "K4sUYtvNdiwHZTTakoo7m8pBF7dE9Guxjtcc42vwBSArsYrfstFcMaVwwth1Ohh/\n" +
            "vO1W5EmMzzsqqm7DYPCVFapwV7wlveYFyD5e9ZVb/im8s+2NHg6PY5L1ke+JN+zx\n" +
            "75M54nGezk+1pJcy05r66a56Wyh85RgMUok1XMPbiVmhA8TVwlCZGnfXetsSsFKg\n" +
            "FjAGD+DdLCdkj9TH2tG7pewlEDNjVM+iWJA8Tmt/H+n4tL1LedzGs1KkwEZKEcxZ\n" +
            "txDdBxPWFQDK3UloOwaP6y0CAwEAAQ==\n" +
            "-----END PUBLIC KEY-----\n";
    private static final String badKey           = "IAMNOTAKEY";

    @Test
    public void TestGoodPublicKey() throws Exception{

        PublicKey pub = new PublicKey(goodPublicKey.getBytes());

        Assert.assertTrue("Valid public key should not be empty",!pub.isEmpty());

        Assert.assertTrue("Public Key does not survive round trip from string and back",pub.string().equals(goodPublicKey));

        Assert.assertTrue("Failed to create RSA public key",new PublicKey(pub.getCryptoKey()).string().equals(pub.string()));

    }

    @Test
    public void TestBadPublicKey() throws Exception{

        PublicKey pub = new PublicKey(badKey.getBytes());

        new PublicKey(new RSAPublicKeyImpl(new byte[]{}));
    }

    @Test
    public void TestMinPublicKeyLength() throws Exception{

        PublicKey.MinPublicKeySize = 2047;

        PublicKey pub = new PublicKey(goodPublicKey.getBytes());
    }
}
