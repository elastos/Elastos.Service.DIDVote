/**
 * Copyright (c) 2017-2019 The Elastos Developers
 * <p>
 * Distributed under the MIT software license, see the accompanying file
 * LICENSE or https://opensource.org/licenses/mit-license.php
 */
package org.elastos.crypto;

import org.bouncycastle.openssl.PEMParser;

import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * clark
 * <p>
 * 3/7/19
 */
public class Kit {

    public static Object readPemObject(InputStream is) {
        try {
            InputStreamReader isr = new InputStreamReader(is, "UTF-8");
            PEMParser pemParser = new PEMParser(isr);

            Object obj = pemParser.readObject();
            if (obj == null) {
                throw new Exception("No PEM object found");
            }
            return obj;
        } catch (Throwable ex) {
            throw new RuntimeException("Cannot read PEM object from input data", ex);
        }
    }
}
