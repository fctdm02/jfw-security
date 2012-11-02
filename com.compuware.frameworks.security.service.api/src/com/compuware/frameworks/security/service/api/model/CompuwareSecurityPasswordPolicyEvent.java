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
@XmlSeeAlso({CompuwareSecurityPasswordPolicyCreatedEvent.class,CompuwareSecurityPasswordPolicyDeletedEvent.class,CompuwareSecurityPasswordPolicyUpdatedEvent.class})
public abstract class CompuwareSecurityPasswordPolicyEvent extends CompuwareSecurityUserInitiatedEvent {

    /* */
    private static final long serialVersionUID = 1L;
    
    /* */
    private String subjectPasswordPolicyName;
    
    /**
     * 
     */
    protected CompuwareSecurityPasswordPolicyEvent() {
        super();
    }
    
    /**
     * @param passwordPolicy
     * @param initiatingUsername
     * @param originatingIpAddress
     * @param originatingHostname
     * @param eventDetails
     * @param realmName
     */
    public CompuwareSecurityPasswordPolicyEvent(
        PasswordPolicy passwordPolicy,
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
        
        this.subjectPasswordPolicyName = passwordPolicy.getName();
    }
    
    /**
     * @return the subjectPasswordPolicyName
     */
    @XmlAttribute
    public final String getSubjectPasswordPolicyName() {
        return this.subjectPasswordPolicyName;
    }

    /**
     * @param subjectPasswordPolicyName the subjectPasswordPolicyName to set
     */
    protected final void setSubjectPasswordPolicyName(String subjectPasswordPolicyName) {
        this.subjectPasswordPolicyName = subjectPasswordPolicyName;
    }
    
    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
   public String toString() {
      
      StringBuilder sb = new StringBuilder();
      sb.append("{");
      sb.append(this.getClass().getSimpleName());
      sb.append(": subjectPasswordPolicyName: ");
      sb.append(this.subjectPasswordPolicyName);
      sb.append(", ");
      super.toString(sb);
      sb.append("}");
      return sb.toString();
   }  
}