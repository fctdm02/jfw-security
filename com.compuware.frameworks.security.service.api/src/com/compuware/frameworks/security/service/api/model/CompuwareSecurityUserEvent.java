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

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;


/**
 * 
 * @author tmyers
 *
 */
@XmlRootElement
@XmlSeeAlso({CompuwareSecurityUserCreatedEvent.class,CompuwareSecurityUserDeletedEvent.class,CompuwareSecurityUserUpdatedEvent.class})
public abstract class CompuwareSecurityUserEvent extends CompuwareSecurityUserInitiatedEvent {

    /* */
    private static final long serialVersionUID = 1L;
    
    /* */
    private String subjectUsername;
    
    /**
     * 
     */
    protected CompuwareSecurityUserEvent() {
        super();
    }

    /**
     * @param abstractUser
     * @param initiatingUsername
     * @param originatingIpAddress
     * @param originatingHostname
     * @param eventDetails
     * @param realmName
     */
    public CompuwareSecurityUserEvent(
        AbstractUser abstractUser,
        String initiatingUsername,
        String originatingIpAddress,
        String originatingHostname,
        String eventDetails,
        String realmName) {
        
        super(
            initiatingUsername,
            originatingIpAddress,
            originatingHostname,
            eventDetails,
            realmName);
        
        this.subjectUsername = abstractUser.getUsername();
    }
    
    /**
     * @return the subjectUsername
     */
    @XmlAttribute
    public final String getSubjectUsername() {
        return subjectUsername;
    }

    /**
     * @param subjectUsername the subjectUsername to set
     */
    protected final void setSubjectUsername(String subjectUsername) {
        this.subjectUsername = subjectUsername;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
   public String toString() {
      
      StringBuilder sb = new StringBuilder();
      sb.append("{");
      sb.append(this.getClass().getSimpleName());
      sb.append(": subjectUsername: ");
      sb.append(this.subjectUsername);
      sb.append(", ");
      super.toString(sb);
      sb.append("}");
      return sb.toString();
   }  
}