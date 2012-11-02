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
package com.compuware.frameworks.security.crypto;

import com.compuware.frameworks.security.AbstractCompuwareSecurityPrivateKey;

/**
 * 
 * @author tmyers
 * 
 * @see <a href="http://java.sun.com/developer/technicalArticles/Security/AES/AES_v1.html">Using AES with Java Technology</a>
 */
public final class CompuwareSecurityPrivateKey extends AbstractCompuwareSecurityPrivateKey {

    private static final char passwordChar1  = '5';
    private static final char passwordChar2  = 'J';
    private static final char passwordChar3  = 'f';
    private static final char passwordChar4  = 'W';
    private static final char passwordChar5  = 'S';
    private static final char passwordChar6  = 'e';
    private static final char passwordChar7  = 'r';
    private static final char passwordChar8  = 'i';
    private static final char passwordChar9  = 't';
    private static final char passwordChar10 = 'Y';
    private static final char passwordChar11 = '3';
    private static final char passwordChar12 = '1';
    private static final String saltString = "300";
    
    private static CompuwareSecurityPrivateKey instance = new CompuwareSecurityPrivateKey(
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
            passwordChar12,
            saltString);
    
    private CompuwareSecurityPrivateKey(
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
        super(
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
            passwordChar12,
            saltString);
    }
    
    /**
     * 
     * @return
     */
    public static CompuwareSecurityPrivateKey getInstance() {
        return instance;
    }    
}