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
package com.compuware.frameworks.security.api.crypto;

import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.Key;

import javax.crypto.Cipher;

/**
 * This class provides methods for encrypting/decrypting text using a private key that is
 * passed in by the caller.
 * @author tmyers
 */
public final class EncryptDecrypt {
    
    /* */
    private static final int TWO_FOURTH_POWER = 16;
    
    /* */
    private static final int TWO_SEVENTH_POWER = 128;
    
    /* */
    private static final int TWO_EIGHTH_POWER = 256;
    
    /* */
    private static final String UTF8_CHARSET = "UTF-8";
    
    /*
     * 
     */
    private EncryptDecrypt() {
        
    }

    /**
     * 
     * @param text
     * @param key
     * @return
     */
    public static String encryptAndUrlEncodeText(String text, Key key) {
        String encryptedText = encryptText(text, key);
        try {
            return URLEncoder.encode(encryptedText, UTF8_CHARSET);
        } catch (UnsupportedEncodingException uee) {
            throw new IllegalStateException("Could not URL encode, error: " + uee.getMessage(), uee);
        }
    }

    /**
     * 
     * @param urlEncodedText
     * @param key
     * @return
     */
    public static String urlDecodeAndDecryptText(String urlEncodedText, Key key) {
        try {
            String encryptedText = URLDecoder.decode(urlEncodedText, UTF8_CHARSET);
            return decryptText(encryptedText, key);
        } catch (UnsupportedEncodingException uee) {
            throw new IllegalStateException("Could not URL decode, error: " + uee.getMessage(), uee);
        }
    }
    
    /**
     * @param text
     * @param key
     * @return String
     */
    public static String encryptText(String text, Key key) {
        try {
            byte[] encryptedBytes = encrypt(text, key);
            return convertBytesToHexString(encryptedBytes);
        } catch (Exception e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        }
    }

    /**
     * @param encryptedText
     * @param key
     * @return String
     */
    public static String decryptText(String encryptedText, Key key) {
        try {
            byte[] encryptedBytes = convertHexStringToBytes(encryptedText);
            byte[] decryptedBytes = decrypt(encryptedBytes, key);
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        }
    }

    /*
     * @param text
     * @param key
     * @return byte[]
     */
    private static byte[] encrypt(String text, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        }
    }

    /*
     * @param encryptedBytes
     * @param key
     * @return
     */
    private static byte[] decrypt(byte[] encryptedBytes, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(encryptedBytes);
        } catch (Exception e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        }
    }

    /*
     * Convert the encrypted password to file storable hex characters.
     * 
     * @param byteArray
     * @return
     */
    private static String convertBytesToHexString(byte[] byteArray) {
        StringWriter sw = null;
        try {
            sw = new StringWriter();
            int tempint = 0;
            for (int i = 0; i < byteArray.length; i++) {
                tempint = new Byte(byteArray[i]).intValue();
                String s = Integer.toHexString(tempint);
                if (s.length() > 2) {
                    sw.write(s.substring(s.length() - 2));
                } else if (s.length() == 2) {
                    sw.write(s);
                } else if (s.length() == 1) {
                    sw.write("0");
                    sw.write(s);
                }
            }
            return sw.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        } finally {
            if (sw != null) {
                try {
                    sw.close();    
                } catch (Exception e) {
                    throw new IllegalStateException("Could not close StringWriter", e);
                }
            }
        }
        
    }

    /*
     * Convert the file storable hex characters back to the byte array used for encryption/decryption.
     * 
     * @param hexString
     * @return
     */
    private static byte[] convertHexStringToBytes(String hexString) {
        char[] car = new char[2];
        int rc, i, offset;
        int tempint;
        StringReader strr = null;
        
        // Read two characters at a time, and convert it to byte representation
        try {
            strr = new StringReader(hexString);
            byte value[] = new byte[hexString.length() / 2];
            offset = 0;
            rc = strr.read(car, offset, 2);
            i = 0;
            while (rc != -1) {
                String ns = new String(car);
                tempint = Integer.parseInt(ns, TWO_FOURTH_POWER);
                if (tempint > TWO_SEVENTH_POWER) {
                    tempint = tempint - TWO_EIGHTH_POWER;
                }
                value[i] = Integer.valueOf(tempint).byteValue();
                i++;
                //The offset will be incremented automatically. Do not increment
                rc = strr.read(car, offset, 2);
            }
            return (value);
        } catch (Exception e) {
            throw new IllegalStateException(e.getLocalizedMessage(), e);
        } finally {
            if (strr != null) {
                strr.close();
            }
        }
    }
}