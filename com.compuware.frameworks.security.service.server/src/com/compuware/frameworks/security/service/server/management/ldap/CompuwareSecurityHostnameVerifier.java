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
package com.compuware.frameworks.security.service.server.management.ldap;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.apache.log4j.Logger;

/**
 * 
 * @author tmyers
 * 
 * @see http://docs.oracle.com/javase/jndi/tutorial/ldap/ext/starttls.html
 * @see http://directory.apache.org/apacheds/1.5/33-how-to-enable-ssl.html
 * <pre>
 * Step 1: Use Apache Directory Studio to view entry for "uid=admin,ou=system"
 * Step 2: View the X.509 cert.
 * Step 3: Export the cert, save as "apacheds_cert.der"
 * Step 4: Use keytool to import the cert into a new keystore (answer "yes" as
 * to whether you trust the cert)
 * 
    D:\>dir *.der
     Volume in drive D is DATA
     Volume Serial Number is C629-A725
    
     Directory of D:\
    
    02/06/2012  12:54 PM               375 apacheds_cert.der
                   1 File(s)            375 bytes
                   0 Dir(s)  42,857,369,600 bytes free
    
    D:\>keytool -import -file apacheds_cert.der -alias css -keystore trusted.ks -sto
    repass secret
    Owner: CN=ApacheDS, OU=Directory, O=ASF, C=US
    Issuer: CN=ApacheDS, OU=Directory, O=ASF, C=US
    Serial number: 135536eb1c4
    Valid from: Mon Feb 06 11:10:57 EST 2012 until: Tue Feb 05 11:10:57 EST 2013
    Certificate fingerprints:
             MD5:  A7:C4:ED:C1:86:AA:91:E1:D9:18:3A:BF:F8:0B:3C:79
             SHA1: 0A:D8:78:B4:5E:26:97:A0:B2:52:36:7D:47:43:B9:85:F2:9A:9C:E9
             Signature algorithm name: SHA1withRSA
             Version: 1
    Trust this certificate? [no]:  yes
    Certificate was added to keystore
    
    Step 5: When running test/client/whatever, use the following system property to 
    use the trusted keystore (that contains the apache ds server public key)
    -Djavax.net.ssl.trustStore=trusted.ks 
 * </pre>
 * 
 * 
 */
public final class CompuwareSecurityHostnameVerifier implements HostnameVerifier {

    /* */
    private final Logger logger = Logger.getLogger(CompuwareSecurityHostnameVerifier.class);
    
    /*
     * (non-Javadoc)
     * 
     * @see javax.net.ssl.HostnameVerifier#verify(java.lang.String,
     * javax.net.ssl.SSLSession)
     */
    public boolean verify(String hostname, SSLSession sslSession) {
        
        logger.warn("Skipping LDAP Server Certificate validation for hostname: [" + hostname + "] and session peer host: [" + sslSession.getPeerHost() + "].");
        return true;
    }
}