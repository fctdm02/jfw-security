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
package com.compuware.frameworks.security.service.api.model;

/**
 * 
 * @author tmyers
 * 
 */
public final class MigrationGroup extends AbstractMigrationPrincipal {
    
    /* */
    private static final long serialVersionUID = 1L;
    
    /* */
    private String memberUsers = "";
    
    /**
     * 
     */
    public MigrationGroup() {        
    }
    
    /**
     * @return the memberUsers
     */
    public String getMemberUsers() {
        return this.memberUsers;
    }

    /**
     * @param memberUsers the memberUsers to set
     */
    public void setMemberUsers(String memberUsers) {
        if (memberUsers != null) {
            this.memberUsers = memberUsers;    
        }
    }    
 
    /**
     * @return String
     */
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        sb.append(", memberUsers: ");
        sb.append(this.memberUsers);
        return sb.toString();
    }
}