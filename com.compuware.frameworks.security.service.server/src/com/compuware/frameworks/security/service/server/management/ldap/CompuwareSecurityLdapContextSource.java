/**
* Copyright (c) 1991-${year} Compuware Corporation. All rights reserved.
 * Unpublished - rights reserved under the Copyright Laws of the United States.
 *
 *
 * U.S. GOVERNMENT RIGHTS-Use, duplication, or disclosure by the U.S. Government is
 * subject to restrictions as set forth in Compuware Corporation license agreement
 * and as provided for in DFARS 227.7202-1(a) and 227.7202-3(a) (1995),
 * DFARS 252.227-7013(c)(1)(ii)(OCT 1988), FAR 12.212(a)(1995), FAR 52.227-19,
 * or FAR 52.227-14 (ALT III), as applicable. Compuware Corporation.
 */
package com.compuware.frameworks.security.service.server.management.ldap;

import java.util.Hashtable;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;

import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;

import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityLdapConfiguration;
import com.compuware.frameworks.security.service.api.exception.ServiceException;

/**
 * Provides a thin wrapper around Spring's <code>DefaultSpringSecurityContextSource</code> 
 * and whose only real purpose is to modify the base environment properties with respect to 
 * SSL. 
 * 
 * @author tmyers
 */
public final class CompuwareSecurityLdapContextSource extends DefaultSpringSecurityContextSource {
    
    /* */
    private Map<String, String> baseEnvironmentProperties = new Hashtable<String, String>();
    
    /**
     * Create and initialize an instance which will connect to the supplied LDAP URL.
     *
     * @param providerUrl an LDAP URL of the form <code>ldap://localhost:389/base_dn<code>
     * @param userDn
     * @param clearTextPassword
     * @param referral
     * @param useTls
     * @param performServerCertificateValidation If <code>true</code>, validates the certificate of the LDAP Server (for either SSL or TLS)
     * @param baseEnvironmentProperties
     */
    public CompuwareSecurityLdapContextSource(
    	String providerUrl,
        String ldapServiceAccountUserDn,
        String ldapServiceAccountClearTextPassword,        
        String referral,
        String useTls,
        String performServerCertificateValidation,
        Map<String, String> baseEnvironmentProperties) {
        super(providerUrl);
        
        setUserDn(ldapServiceAccountUserDn);
        setPassword(ldapServiceAccountClearTextPassword);
        setReferral(referral);
        
        if (useTls == null || (!useTls.trim().equalsIgnoreCase("true") && !useTls.trim().equalsIgnoreCase("false"))) {
            throw new ServiceException("'useTls' parameter for CSS CompuwareSecurityLdapContextSource must be non-null and either 'true' or 'false', but was: " + useTls);
        }
        boolean bUseTls = Boolean.valueOf(useTls);
        
        if (performServerCertificateValidation == null || (!performServerCertificateValidation.trim().equalsIgnoreCase("true") && !performServerCertificateValidation.trim().equalsIgnoreCase("false"))) {
            throw new ServiceException("'performServerCertificateValidation' parameter for CSS CompuwareSecurityLdapContextSource must be non-null and either 'true' or 'false', but was: " + performServerCertificateValidation);
        }
        boolean bPerformServerCertificateValidation = Boolean.valueOf(performServerCertificateValidation);
        
        if (providerUrl.startsWith(ICompuwareSecurityLdapConfiguration.LDAP_URL_SSL_PROTOCOL_PREFIX) && bUseTls) {
            throw new ServiceException("The use of the '" 
                + ICompuwareSecurityLdapConfiguration.LDAP_URL_SSL_PROTOCOL_PREFIX 
                + ", LDAP URL protocol and 'useTls=true' is invalid.  Please specify one or the other, but not both.");
        }
                
        this.baseEnvironmentProperties = baseEnvironmentProperties;
        setBaseEnvironmentProperties(baseEnvironmentProperties);

        
        addPropertyToBaseEnvironment("javax.net.debug", "ssl,handshake,record");
        System.setProperty("javax.net.debug", "ssl,handshake,record");
        
        
        // Don't use a timeout when using SSL, as JNDI throws a SocketException when setting a timeout.  
        // See: http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg1PK09347 for details        
        if (providerUrl.startsWith(ICompuwareSecurityLdapConfiguration.LDAP_URL_SSL_PROTOCOL_PREFIX)) {
            
            removePropertyFromBaseEnvironment("java.naming.ldap.referral.limit");
            removePropertyFromBaseEnvironment("com.sun.jndi.ldap.connect.timeout");
            
            // If we are to disable server certificate validation for SSL, we need to use our socket factory 
            // that skips the verification (based upon the public key of the cert).
            if (!bPerformServerCertificateValidation) {
                addPropertyToBaseEnvironment("java.naming.ldap.factory.socket", CompuwareSecuritySslSocketFactory.class.getName());    
            }
        } else {
            removePropertyFromBaseEnvironment("java.naming.ldap.factory.socket");
        }

        // http://docs.oracle.com/javase/jndi/tutorial/ldap/ext/starttls.html
        if (bUseTls) {
            
            DefaultTlsDirContextAuthenticationStrategy authenticationStrategy = new DefaultTlsDirContextAuthenticationStrategy();
            
            // If we are to disable server certificate validation for TLS, we need to use our socket factory 
            // that skips the verification (based upon the public key of the cert).
            if (!bPerformServerCertificateValidation) {
                HostnameVerifier hostnameVerifier = new CompuwareSecurityHostnameVerifier();                
                authenticationStrategy.setHostnameVerifier(hostnameVerifier);
            }
            
            this.setAuthenticationStrategy(authenticationStrategy);
        }
        
    }

    /**
     * 
     * @param key
     * @param value
     * 
     * @return
     */
    public Map<String, String> addPropertyToBaseEnvironment(String key, String value) {
        this.baseEnvironmentProperties.put(key, value);
        setBaseEnvironmentProperties(baseEnvironmentProperties);
        return this.baseEnvironmentProperties;
    }
    
    /**
     * 
     * @param key
     * 
     * @return
     */
    public Map<String, String> removePropertyFromBaseEnvironment(String key) {
        this.baseEnvironmentProperties.remove(key);
        setBaseEnvironmentProperties(baseEnvironmentProperties);
        return this.baseEnvironmentProperties;
    }
    
    /**
     * 
     * @return
     */
    public Map<String, String> getBaseEnvironmentProperties() {
        return this.baseEnvironmentProperties;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{CompuwareSecurityLdapContextSource: ");
        sb.append(this.baseEnvironmentProperties);
        return sb.toString();
    }
}