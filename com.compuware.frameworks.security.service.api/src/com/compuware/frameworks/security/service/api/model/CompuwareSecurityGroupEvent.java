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
@XmlSeeAlso({CompuwareSecurityGroupCreatedEvent.class,CompuwareSecurityGroupDeletedEvent.class,CompuwareSecurityGroupUpdatedEvent.class})
public abstract class CompuwareSecurityGroupEvent extends CompuwareSecurityUserInitiatedEvent {

    /* */
    private static final long serialVersionUID = 1L;
    
    /* */
    private String subjectGroupname;
    
    /**
     * 
     */
    protected CompuwareSecurityGroupEvent() {
        super();
    }

    /**
     * 
     * @param abstractGroup
     * @param initiatingUsername
     * @param originatingIpAddress
     * @param originatingHostname
     * @param eventDetails
     * @param realmName
     */
    public CompuwareSecurityGroupEvent(
        AbstractGroup abstractGroup,
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
        
        this.subjectGroupname = abstractGroup.getGroupname();
    }
    
    /**
     * @return the subjectGroupname
     */
    @XmlAttribute
    public final String getSubjectGroupname() {
        return subjectGroupname;
    }

    /**
     * @param subjectGroupname the subjectGroupname to set
     */
    protected final void setSubjectGroupname(String subjectGroupname) {
        this.subjectGroupname = subjectGroupname;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
   public String toString() {
      
      StringBuilder sb = new StringBuilder();
      sb.append("{");
      sb.append(this.getClass().getSimpleName());
      sb.append(": subjectGroupname: ");
      sb.append(this.subjectGroupname);
      sb.append(", ");
      super.toString(sb);
      sb.append("}");
      return sb.toString();
   }  
}