/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2010 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author tmyers
 * 
 * @see <a href="http://java.sun.com/developer/technicalArticles/Security/AES/AES_v1.html">Using AES with Java Technology</a>
 */
public abstract class AbstractCompuwareSecurityPrivateKey {
    
    /** */
    public static final String SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA1";
    
    /** */
    public static final String ALGORITHM = "AES";
    
    /* */
    private SecretKeySpec secretKeySpec;
    
    /**
     * 
     * @param passwordChar1
     * @param passwordChar2
     * @param passwordChar3
     * @param passwordChar4
     * @param passwordChar5
     * @param passwordChar6
     * @param passwordChar7
     * @param passwordChar8
     * @param passwordChar9
     * @param passwordChar10
     * @param passwordChar11
     * @param passwordChar12
     * @param saltString
     */
    protected AbstractCompuwareSecurityPrivateKey(
        char passwordChar1,
        char passwordChar2,
        char passwordChar3,
        char passwordChar4,
        char passwordChar5,
        char passwordChar6,
        char passwordChar7,
        char passwordChar8,
        char passwordChar9,
        char passwordChar10,
        char passwordChar11,
        char passwordChar12,
        String saltString) {
            
        SecretKeyFactory secretKeyFactory;
        try {
            char[] password = {
                passwordChar1,
                passwordChar2,
                passwordChar3,
                passwordChar4,
                passwordChar5,
                passwordChar6,
                passwordChar7,
                passwordChar8,
                passwordChar9,
                passwordChar10,
                passwordChar11,
                passwordChar12};
            byte[] salt = saltString.getBytes();
            int iterationCount = 1024;
            int keyLength = 128;        
            KeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
            
            secretKeyFactory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITHM);
            SecretKey tempSecretKey = secretKeyFactory.generateSecret(keySpec);
            SecretKey secretKey = new SecretKeySpec(tempSecretKey.getEncoded(), ALGORITHM);
            this.secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), ALGORITHM);
            
        } catch (NoSuchAlgorithmException e) {
            
            throw new IllegalStateException("Could not initialize private key with factory instance: [" 
                + SECRET_KEY_FACTORY_ALGORITHM 
                + "] and algorithm: [" 
                + ALGORITHM 
                + "], error: " 
                + e.getMessage(), e);
            
        } catch (InvalidKeySpecException e) {
            
            throw new IllegalStateException("Could not initialize private key with factory instance: [" 
                + SECRET_KEY_FACTORY_ALGORITHM 
                + "] and algorithm: [" 
                + ALGORITHM 
                + "], error: " 
                + e.getMessage(), e);
        }
    }
        
    /**
     * 
     * @return
     */
    public SecretKeySpec getKey() {
        return this.secretKeySpec;
    }
}