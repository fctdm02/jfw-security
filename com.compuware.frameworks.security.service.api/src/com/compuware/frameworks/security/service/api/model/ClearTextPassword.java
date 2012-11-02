/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2012 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.api.model;


/**
 * 
 * @author tmyers
 * 
 */
public final class ClearTextPassword {
    
    /* */
    private static final String PROTECTED_STRING_VALUE = "[PROTECTED]";
    
    /* */
    private String clearTextPassword;
    
    /**
     * 
     * @param clearTextPassword
     */
    public ClearTextPassword(String clearTextPassword) {
        this.clearTextPassword = clearTextPassword;
    }
    
    /**
     * 
     * @return
     */
    public String getClearTextPassword() {
        return this.clearTextPassword;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(Object that) {
        if (that == null) {
            return false;
        }
        if (that instanceof ClearTextPassword) {
            ClearTextPassword thatClearTextPassword = (ClearTextPassword)that;
            return this.getClearTextPassword().equals(thatClearTextPassword.getClearTextPassword());
        }
        return false;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.getClearTextPassword().hashCode();
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return PROTECTED_STRING_VALUE;
    }
}