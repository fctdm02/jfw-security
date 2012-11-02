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

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;


/**
 * 
 * @author tmyers
 *
 */
@XmlRootElement
@XmlSeeAlso({CompuwareSecuritySessionAccessedEvent.class,CompuwareSecuritySessionCreatedEvent.class,CompuwareSecuritySessionInvalidatedEvent.class})
public abstract class CompuwareSecuritySessionEvent extends CompuwareSecurityEvent {

    /* */
    private static final long serialVersionUID = 1L;
    
    /* */
    private String sessionId;
    
    /**
     * 
     */
    protected CompuwareSecuritySessionEvent() {
        super();
    }

    /**
     * @param sessionId
     * @param realmName
     */
    public CompuwareSecuritySessionEvent(
        String sessionId,
        String realmName) {
        
        super(
            Long.toString(System.currentTimeMillis()),
            realmName);
        
        this.sessionId = sessionId;
    }
    
    /**
     * @return the sessionId
     */
    @XmlElement
    public final String getSessionId() {
        return this.sessionId;
    }

    /**
     * @param sessionId the sessionId to set
     */
    protected final void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
   public String toString() {
      
      StringBuilder sb = new StringBuilder();
      sb.append("{");
      sb.append(this.getClass().getSimpleName());
      sb.append(": sessionId: ");
      sb.append(this.sessionId);
      sb.append(", ");
      super.toString(sb);
      sb.append("}");
      return sb.toString();
   }  
}