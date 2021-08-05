package com.nimbusds.jose.crypto.impl;

/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */


import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Container;
import junit.framework.TestCase;

import javax.crypto.SecretKey;


/**
 * Tests the authenticated XC20P encryption and decryption methods. Uses test
 * vectors from draft-irtf-cfrg-xchacha-03, appendix A.
 *
 * @author Alexander Martynov
 * @version 2021-08-04
 */
public class XC20PTest extends TestCase {

    public void testEncryptDecrypt() throws JOSEException {
        SecureRandom secureRandom = new SecureRandom();
        String plainText = "Hello, world!";


        // secret key
        SecretKey key = ContentCryptoProvider.generateCEK(EncryptionMethod.XC20P, secureRandom);

        // aad
        byte[] aad = new byte[128];
        secureRandom.nextBytes(aad);

        // IV
        Container<byte[]> ivContainer = new Container<>(null);

        AuthenticatedCipherText authenticatedCipherText = XC20P.encryptAuthenticated(
                key,
                ivContainer,
                plainText.getBytes(StandardCharsets.UTF_8),
                aad
        );

        byte[] decrypted = XC20P.decryptAuthenticated(
                key,
                ivContainer.get(),
                authenticatedCipherText.getCipherText(),
                aad,
                authenticatedCipherText.getAuthenticationTag()
        );

        String clearText = new String(decrypted, StandardCharsets.UTF_8);
        assertEquals(plainText, clearText);
    }
}