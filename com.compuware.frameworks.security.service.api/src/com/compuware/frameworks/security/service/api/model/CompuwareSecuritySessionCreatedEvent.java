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
package com.compuware.frameworks.security.service.api.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;


/**
 * 
 * @author tmyers
 *
 */
@XmlRootElement
public final class CompuwareSecuritySessionCreatedEvent extends CompuwareSecuritySessionEvent {

    /** */
    private static final long serialVersionUID = 1L;
    
    /* */
    private String username;
    
    /**
     * 
     */
    protected CompuwareSecuritySessionCreatedEvent() {
        super();
    }

    /**
     * @param username
     * @param sessionId
     * @param realmName
     */
    public CompuwareSecuritySessionCreatedEvent(
        String username,
        String sessionId,
        String realmName) {
        
        super(
            sessionId,    
            realmName);
    }
    
    /**
     * 
     * @return
     */
    @XmlElement
    public String getUsername() {
        return this.username;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
   public String toString() {
      
      StringBuilder sb = new StringBuilder();
      sb.append("{");
      sb.append(this.getClass().getSimpleName());
      sb.append(": username: ");
      sb.append(this.username);
      sb.append(", ");
      super.toString(sb);
      sb.append("}");
      return sb.toString();
   }     
}