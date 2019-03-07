/**
 * Copyright (c) 2017-2019 The Elastos Developers
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package org.elastos.crypto;


import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import sun.security.util.DerValue;
import sun.security.x509.X509Key;

import java.io.*;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;

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
     * @param pem
     * @throws Exception
     */
    public PublicKey(byte[] pem) throws Exception {
        PemReader reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(pem)));
        PemObject obj = reader.readPemObject();
        if (!"PUBLIC KEY".equals(obj.getType())){
            throw new RuntimeException(ErrPublicKeyInvalidPEM.getMessage() + " Actual type :" + obj.getType());
        }
        this.pub = obj.getContent();
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

    public String string() throws Exception{
        PemObject pemObject = new PemObject("PUBLIC KEY", this.pub);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        String pemString = stringWriter.toString();
        return pemString;
    }

    public byte[] getSHA256() throws Exception{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(this.string().getBytes());
        byte[] digieted  = md.digest();
        return Hex.encodeHexString(digieted).getBytes();
    }

    public static AsymmetricKeyParameter loadPublicKey(String publicKey) throws Exception{
        InputStream is = new DataInputStream(new ByteArrayInputStream(publicKey.getBytes("utf-8")));
        SubjectPublicKeyInfo spki = (SubjectPublicKeyInfo) Kit.readPemObject(is);
        return PublicKeyFactory.createKey(spki);
    }
}
