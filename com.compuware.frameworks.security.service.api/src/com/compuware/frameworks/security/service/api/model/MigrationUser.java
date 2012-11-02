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
public class MigrationUser extends AbstractMigrationPrincipal {

    /* */
    private static final long serialVersionUID = 1L;

    /* */
    private String firstName;
    
    /* */
    private String lastName;
    
    /* */
    private String emailAddress = "";
    
    /* */
    private String clearTextPassword;
    
    /* If true, then firstName, lastName, emailAddress and clearTextPassword are all ignored. */
    private boolean isLdapUser = false;
    
    /**
     * 
     */
    public MigrationUser() {        
    }
    
    /**
     * @return the firstName
     */
    public String getFirstName() {
        if (this.firstName == null) {
            return getPrincipalName();
        }
        return this.firstName;
    }

    /**
     * @param firstName the firstName to set
     */
    public void setFirstName(String firstName) {
        this.firstName = DomainObject.setOptionalStringValue(firstName);    
    }

    /**
     * @return the lastName
     */
    public String getLastName() {
        if (this.lastName == null) {
            return getPrincipalName();
        }        
        return this.lastName;
    }

    /**
     * @param lastName the lastName to set
     */
    public void setLastName(String lastName) {
        this.lastName = DomainObject.setOptionalStringValue(lastName);
    }

    /**
     * @return the emailAddress
     */
    public String getEmailAddress() {
        return this.emailAddress;
    }

    /**
     * @param emailAddress the emailAddress to set
     */
    public void setEmailAddress(String emailAddress) {
        this.emailAddress = DomainObject.setOptionalStringValue(emailAddress);
    }

    /**
     * @return the clearTextPassword
     */
    public String getClearTextPassword() {
        return this.clearTextPassword;
    }

    /**
     * @param clearTextPassword the clearTextPassword to set
     */
    public void setClearTextPassword(String clearTextPassword) {
        this.clearTextPassword = clearTextPassword;
    }

    /**
     * @return the isLdapUser
     */
    public boolean getIsLdapUser() {
        return this.isLdapUser;
    }

    /**
     * @param isLdapUser the isLdapUser to set
     */
    public void setIsLdapUser(boolean isLdapUser) {
        this.isLdapUser = isLdapUser;
    }
    
    /**
     * @return String
     */
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        sb.append(", firstName: ");
        sb.append(this.firstName);
        sb.append(", lastName: ");
        sb.append(this.lastName);
        sb.append(", emailAddress: ");
        sb.append(this.emailAddress);
        sb.append(", clearTextPassword: ");
        sb.append(this.clearTextPassword);        
        sb.append(", isLdapUser: ");
        sb.append(this.isLdapUser);                
        return sb.toString();
    }
}