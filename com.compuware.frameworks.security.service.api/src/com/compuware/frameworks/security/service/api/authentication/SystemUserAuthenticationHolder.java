/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product emails are trademarks of their respective owners.
 * 
 * Copyright 2012 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.api.authentication;

import java.util.HashMap;
import java.util.Map;

import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;

/**
 * 
 * @author tmyers
 * 
 */
public final class SystemUserAuthenticationHolder {

    /* */
    private static final Map<String, CompuwareSecurityAuthenticationToken> LOCAL_SECURITY_CLIENT_SYSTEM_USER_AUTHENTICATION_MAP = new HashMap<String, CompuwareSecurityAuthenticationToken>();
    
    /* */
    private static final ThreadLocal<CompuwareSecurityAuthenticationToken> SYSTEM_USER_AUTHENTICATION_HOLDER = new InheritableThreadLocal<CompuwareSecurityAuthenticationToken>();

    /**
     * 
     * @return
     */
    public synchronized static CompuwareSecurityAuthenticationToken getSystemUserAuthenticationToken() {
        return SYSTEM_USER_AUTHENTICATION_HOLDER.get();
    }

    /**
     * 
     * @param compuwareSecurityAuthenticationToken
     */
    public synchronized static void setSystemUserAuthenticationToken(CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken) {
        SYSTEM_USER_AUTHENTICATION_HOLDER.set(compuwareSecurityAuthenticationToken);
    }

    /**
     * @param realmName
     * @return
     */
    public synchronized static final CompuwareSecurityAuthenticationToken getSecurityClientSystemUserAuthentication(String realmName) {
        return LOCAL_SECURITY_CLIENT_SYSTEM_USER_AUTHENTICATION_MAP.get(realmName);
    }
    
    /**
     * @param realmName
     * @param compuwareSecurityAuthenticationToken
     */
    public synchronized static final void setSecurityClientSystemUserAuthentication(String realmName, CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken) {
        LOCAL_SECURITY_CLIENT_SYSTEM_USER_AUTHENTICATION_MAP.put(realmName, compuwareSecurityAuthenticationToken);
    }
}