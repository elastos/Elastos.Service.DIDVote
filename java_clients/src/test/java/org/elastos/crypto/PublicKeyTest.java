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

    private static final String goodPublicKey    = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA31GRu9r2QRA9PtIzMKyV3vloQlrmxRLYIgiUsNg6bNOmTOJ1og+HNpTY8XOujf3KpPS38F1XM3AAJQi3pUjcJEdeiqroFf8b7t2pas1V+Bg2XAWWbfKctpnMuxeIYuJE52KhUK4y+qGaLXI+53oT09w3V4CdeQNZllVL2a6q+6gjpdZ+/YOPQ+dncHtYCxNHu1Idub0EP/ZMkdcHLwpi/gmuw7qvdpQTeiw54krV3MoiZq50ZTxTFRCjFJ+C+pmrYaPygrkCkv3sj3v1Be8k0EBYsMH8yZoigbyE0/SlCH+RGLSiS1yAV+MHcoVMzPFbXnFv9usI3UNVSXrDSzsxYgiDaeX7KVrraKhJrM/LIypZbJDiKLpLzKFEx+SkSQ/3e8eSsedp7N5RSvcz9GU6K4sUYtvNdiwHZTTakoo7m8pBF7dE9Guxjtcc42vwBSArsYrfstFcMaVwwth1Ohh/vO1W5EmMzzsqqm7DYPCVFapwV7wlveYFyD5e9ZVb/im8s+2NHg6PY5L1ke+JN+zx75M54nGezk+1pJcy05r66a56Wyh85RgMUok1XMPbiVmhA8TVwlCZGnfXetsSsFKgFjAGD+DdLCdkj9TH2tG7pewlEDNjVM+iWJA8Tmt/H+n4tL1LedzGs1KkwEZKEcxZtxDdBxPWFQDK3UloOwaP6y0CAwEAAQ==";
    private static final String goodPublicKeySHA = "698274e67a7f9bdb7a19e6b6d12fa07c4b2074b512ce7fa341f865d137e0335a";
    private static final String badKey           = "IAMNOTAKEY";

    @Test
    public void TestGoodPublicKey() throws Exception{

        PublicKey pub = new PublicKey(goodPublicKey.getBytes());

        Assert.assertTrue("Valid public key should not be empty",!pub.isEmpty());

        Assert.assertTrue("Public Key does not survive round trip from string and back",pub.string().equals(goodPublicKey));

        Assert.assertTrue("Failed to create RSA public key",pub.getCryptoKey() != null);

        Assert.assertTrue("Sha256 not match",new String(pub.getSHA256()).equals(goodPublicKeySHA));
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
