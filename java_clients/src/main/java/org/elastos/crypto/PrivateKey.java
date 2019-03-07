/**
 * Copyright (c) 2017-2019 The Elastos Developers
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package org.elastos.crypto;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * clark
 * <p>
 * 3/7/19
 */
public class PrivateKey {

    private byte[] priv;

    public static final Exception ErrPrivatKeyInvalidPEM = new Exception("Could not decode Prviate Key PEM Block");
    public static final Exception ErrPrivatKeyWrongType  = new Exception("Could not find RSA PRIVATE KEY block");
    public static final Exception ErrPrivatKeyGenerate   = new Exception("Could not generate new PrivateKey");
    public static final Exception ErrPrivatKeyCryptoKey  = new Exception("Could not create from rsa.CryptoKey from PrivateKey. Could not parse PrivateKey bytes");
    public static final Exception ErrPrivatKeySign       = new Exception("PrivateKey could not sign bytes");
    public static final Exception ErrPrivateKeySHA256    = new Exception("Invalid SHA256 Hash checksum");
    public static final Exception ErrPrivateKeyLen       = new Exception("Could not determine private key length");

    public PrivateKey(byte[] pem) throws Exception{
        PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(pem)));
        PemObject pemObject = pemReader.readPemObject();
        String type = pemObject.getType();
        if (!"RSA PRIVATE KEY".equals(type)){
            throw new RuntimeException(ErrPrivatKeyWrongType.getMessage()+"Found " + type);
        }
        byte[] content = pemObject.getContent();
        this.priv = content;
    }


    public PrivateKey(int keySize) throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = new SecureRandom();
        keyGen.initialize(keySize,random);
        KeyPair keypair = keyGen.generateKeyPair();
        byte[] privBytes = keypair.getPrivate().getEncoded();
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privBytes);
        ASN1Encodable encodable = pkInfo.parsePrivateKey();
        ASN1Primitive primitive = encodable.toASN1Primitive();
        byte[] privateKeyPKCS1 = primitive.getEncoded();
        this.priv = privateKeyPKCS1;
    }

    public byte[] bytes(){
        return this.priv;
    }

    public java.security.PrivateKey getCryptoKey() throws Exception{
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(this.priv);
        return kf.generatePrivate(ks);
    }

    public boolean isEmpty(){
        if(this.priv == null){
            return true;
        }
        return false;
    }

    public PublicKey publicKey() throws Exception {

        BCRSAPrivateCrtKey privateKey = (BCRSAPrivateCrtKey)getCryptoKey();

        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(privateKey.getModulus(),privateKey.getPublicExponent()));

        return new PublicKey(publicKey);
    }

    public byte[] sign(String data) throws Exception {
        byte[] buf = data.getBytes("utf-8");
        return signBytes(buf);
    }

    public byte[] signBytes(byte[] dataByte) throws Exception{
        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(true, loadPrivateKey(this.string()));
        signer.update(dataByte, 0, dataByte.length);
        byte[] signature = signer.generateSignature();
        return signature;
    }

    private AsymmetricKeyParameter loadPrivateKey(String pem) throws Exception{
        InputStream is = new DataInputStream(new ByteArrayInputStream(pem.getBytes("UTF-8")));
        PEMKeyPair keyPair = (PEMKeyPair) Kit.readPemObject(is);
        PrivateKeyInfo pki = keyPair.getPrivateKeyInfo();
        try {
           return PrivateKeyFactory.createKey(pki);
        } catch (IOException ex) {
            throw new RuntimeException("Cannot create private key object based on input data", ex);
        }
    }


    public String string()throws Exception{
        PemObject pemObject = new PemObject("RSA PRIVATE KEY", this.priv);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        String pemString = stringWriter.toString();
        return pemString;
    }

    public int keyLength() throws Exception{
        return ((BCRSAPrivateCrtKey)getCryptoKey()).getModulus().bitLength();
    }

    //TODO finish method `blindSign` after written rsaBlind class

}
