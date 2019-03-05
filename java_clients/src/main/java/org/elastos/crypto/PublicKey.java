/**
 * Copyright (c) 2017-2019 The Elastos Developers
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package org.elastos.crypto;


import org.apache.commons.codec.binary.Hex;
import sun.security.util.DerValue;
import sun.security.x509.X509Key;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * clark
 * <p>
 * 3/5/19
 */
public class PublicKey {
    private byte[] pub;
    private static final int absoluteMinPublicKeySize = 2048;
    public static int MinPublicKeySize = 4096; // MinPublicKeySize is the recommended minimum public key size -- this can be changed
    public static Exception ErrPublicKeyInvalidPEM = new Exception("Could not decode Public Key PEM Block");
    public static Exception ErrPublicKeyWrongType = new Exception("Could not find RSA PUBLIC KEY block");
    public static Exception ErrPubicMinKeySize = new Exception("Invalid public key - too short");
    public static Exception ErrPublicKeyBase64 = new Exception("Invalid Public Key. Could not read base64 encoded bytes");
    public static Exception ErrPublicKeyLen = new Exception("Could not determine PublicKey key length");
    public static Exception ErrPublicKeyCryptoKey = new Exception("Could not create from rsa.PublicKey from PublicKey. Could not parse PublicKey bytes");

    /**
     * get public key from base64 encoded public key
     * @param base64PublicKey
     * @throws Exception
     */
    public PublicKey(byte[] base64PublicKey) throws Exception {
        Base64.Decoder decoder = Base64.getDecoder();
        this.pub = decoder.decode(base64PublicKey);
        int keyLength= this.keyLength();
        if(MinPublicKeySize < absoluteMinPublicKeySize){
            throw new RuntimeException("MinPublicKeySize has been set less than the allowed absoluteMinPublicKeySize of 2048");
        }
        if(keyLength < absoluteMinPublicKeySize){
            throw new RuntimeException(ErrPubicMinKeySize.getMessage()+" Please use at least %s bits for public-key " + MinPublicKeySize);
        }
    }

    /**
     * get public key bytes from RSAPublicKey
     * @param rsaPub
     * @throws Exception
     */
    public PublicKey(RSAPublicKey rsaPub){
        this.pub = rsaPub.getEncoded();
    }

    public PublicKey(String pemfile) throws Exception{
        this.pub = getPemPublicKey(pemfile).getEncoded();
    }

    public int keyLength()  throws Exception{
        RSAPublicKey rsaPub = this.getCryptoKey();
        return rsaPub.getModulus().bitLength();
    }

    public RSAPublicKey getCryptoKey() throws Exception{
        DerValue derValue = new DerValue(this.pub);
        return (RSAPublicKey)X509Key.parse(derValue);
    }

    public byte[] getPublicKey(){
        return this.pub;
    }

    public boolean isEmpty() {
        if(this.pub == null || this.pub.length == 0){
            return true;
        }
        return false;
    }

    public String string(){
        return Base64.getEncoder().encodeToString(this.pub);
    }

    public byte[] getSHA256() throws Exception{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(this.string().getBytes());
        byte[] digieted  = md.digest();
        return Hex.encodeHexString(digieted).getBytes();
    }

    public  RSAPublicKey getPemPublicKey(String pemfile) throws Exception {
        File f = new File(pemfile);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String temp = new String(keyBytes);
        String publicKeyPEM = temp.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");


        byte [] decoded = Base64.getDecoder().decode(publicKeyPEM);

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }
}
