/**
 * Copyright (c) 2017-2019 The Elastos Developers
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package org.elastos.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import java.util.Base64;

/**
 * clark
 * <p>
 * 3/7/19
 */
public class Signature {

    private byte[] signature;

    public Signature(byte[] base64Signature){
        this.signature =base64Signature;
    }

    public boolean VerifySignature(PublicKey publicKey,String message) throws Exception{
        return verify(message.getBytes("utf-8"),publicKey);
    }

    private boolean verify(byte[] msg,PublicKey publicKey) throws Exception {
        AsymmetricKeyParameter param = PublicKey.loadPublicKey(publicKey.string());
        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(false, param);
        signer.update(msg, 0, msg.length);
        boolean isValidSignature = signer.verifySignature(signature);
        return isValidSignature;
    }

    public String string(){
        return Base64.getEncoder().encodeToString(this.signature);
    }



}
