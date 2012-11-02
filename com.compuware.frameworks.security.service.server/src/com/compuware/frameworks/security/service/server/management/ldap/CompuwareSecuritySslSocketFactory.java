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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * An SSLSocketFactory implementation that accepts server certificates without
 * validation.
 * 
 * @author tmyers
 */
public final class CompuwareSecuritySslSocketFactory extends SSLSocketFactory {

    /* */
    private SSLSocketFactory factory;

    /**
     * 
     */
    public CompuwareSecuritySslSocketFactory() {
        try {
            SSLContext sslcontext = null;
            // here you can instanciate your own ssl context with hardened
            // security and your own trust managers which can check the
            // extension
            // SSLContext sslcontext = SSLSecurityInitializer.getContext();
            if (sslcontext == null) {
                sslcontext = SSLContext.getInstance("TLS");
                sslcontext.init(null, // No KeyManager required
                        new TrustManager[] { new CompuwareSecurityTrustManager() }, new java.security.SecureRandom());
            }

            factory = (SSLSocketFactory) sslcontext.getSocketFactory();

        } catch (Exception e) {
            throw new IllegalStateException("Could not initialize CompuwareSecuritySslSocketFactory, error: " + e.getMessage(), e);
        }
    }

    /*
     * 
     */
    public static SocketFactory getDefault() {
        return new CompuwareSecuritySslSocketFactory();
    }

    /*
     * (non-Javadoc)
     * @see javax.net.ssl.SSLSocketFactory#createSocket(java.net.Socket, java.lang.String, int, boolean)
     */
    public Socket createSocket(Socket socket, String s, int i, boolean flag) throws IOException {
        return factory.createSocket(socket, s, i, flag);
    }

    /*
     * (non-Javadoc)
     * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int, java.net.InetAddress, int)
     */
    public Socket createSocket(InetAddress inaddr, int i, InetAddress inaddr1, int j) throws IOException {
        return factory.createSocket(inaddr, i, inaddr1, j);
    }

    /*
     * (non-Javadoc)
     * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int)
     */
    public Socket createSocket(InetAddress inaddr, int i) throws IOException {
        return factory.createSocket(inaddr, i);
    }

    /*
     * (non-Javadoc)
     * @see javax.net.SocketFactory#createSocket(java.lang.String, int, java.net.InetAddress, int)
     */
    public Socket createSocket(String s, int i, InetAddress inaddr, int j) throws IOException {
        return factory.createSocket(s, i, inaddr, j);
    }

    /*
     * (non-Javadoc)
     * @see javax.net.SocketFactory#createSocket(java.lang.String, int)
     */
    public Socket createSocket(String s, int i) throws IOException {
        return factory.createSocket(s, i);
    }

    /*
     * (non-Javadoc)
     * @see javax.net.ssl.SSLSocketFactory#getDefaultCipherSuites()
     */
    public String[] getDefaultCipherSuites() {
        return factory.getSupportedCipherSuites();
    }

    /*
     * (non-Javadoc)
     * @see javax.net.ssl.SSLSocketFactory#getSupportedCipherSuites()
     */
    public String[] getSupportedCipherSuites() {
        return factory.getSupportedCipherSuites();
    }
}