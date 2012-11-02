/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2011 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.api.model.ws;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.springframework.security.core.GrantedAuthority;

@XmlRootElement
public final class CompuwareGrantedAuthority implements Serializable {
    //~ Instance fields ================================================================================================

    private static final long serialVersionUID = 1L;

    private String authorityName;

    //~ Constructors ===================================================================================================

    public CompuwareGrantedAuthority() {
        this.authorityName = "";
    }
    
    public CompuwareGrantedAuthority(String role) {
        this.authorityName = role;
    }
    
    public CompuwareGrantedAuthority(GrantedAuthority inAuthority){
    	this.authorityName = inAuthority.getAuthority();
    }

    //~ Methods ========================================================================================================

    public boolean equals(Object obj) {
        if (obj instanceof String) {
            return obj.equals(this.authorityName);
        }

        if (obj instanceof GrantedAuthority) {
            GrantedAuthority attr = (GrantedAuthority) obj;

            return this.authorityName.equals(attr.getAuthority());
        }

        return false;
    }

    @XmlElement
    public String getAuthority() {
        return this.authorityName;
    }

    public void setAuthority(String role) {
        this.authorityName = role;
    }

    public int hashCode() {
        return this.authorityName.hashCode();
    }

    public String toString() {
        return this.authorityName;
    }
}
