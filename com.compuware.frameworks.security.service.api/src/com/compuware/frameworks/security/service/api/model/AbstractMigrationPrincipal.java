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

import java.io.Serializable;

/**
 * 
 * @author tmyers
 * 
 */
public abstract class AbstractMigrationPrincipal implements Serializable {

    /* */
    private static final long serialVersionUID = 1L;
    
    /* */
    private String principalName;

    /* */
    private String description = "";
    
    /* */
    private String rolesToAssociateTo = "";
    
    /**
     * 
     */
    public AbstractMigrationPrincipal() {        
    }

    /**
     * @return the principalName
     */
    public final String getPrincipalName() {
        return this.principalName;
    }

    /**
     * @param principalName the principalName to set
     */
    public final void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    /**
     * @return the description
     */
    public final String getDescription() {
        return this.description;
    }

    /**
     * @param description the description to set
     */
    public final void setDescription(String description) {
        if (description != null) {
            this.description = DomainObject.trimString(description);    
        }
    }
    
    /**
     * @return the rolesToAssociateTo
     */
    public String getRolesToAssociateTo() {
        return this.rolesToAssociateTo;
    }

    /**
     * @param rolesToAssociateTo the rolesToAssociateTo to set
     */
    public void setRolesToAssociateTo(String rolesToAssociateTo) {
        if (rolesToAssociateTo != null) {
            this.rolesToAssociateTo = rolesToAssociateTo;    
        }
    }    
    
    /**
     * @return String
     */
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("principalName: ");
        sb.append(this.principalName);
        sb.append(", description: ");
        sb.append(this.description);
        sb.append(", rolesToAssociateTo: ");
        sb.append(rolesToAssociateTo);
        return sb.toString();
    }
}