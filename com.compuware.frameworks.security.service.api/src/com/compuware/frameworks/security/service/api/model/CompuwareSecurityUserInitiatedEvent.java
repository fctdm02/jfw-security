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

import com.compuware.frameworks.security.service.api.exception.ServiceException;


/**
 * 
 * @author tmyers
 *
 */
@XmlRootElement
@XmlSeeAlso({CompuwareSecurityAuthenticationEvent.class,CompuwareSecurityConfigurationEvent.class,CompuwareSecurityGroupEvent.class,CompuwareSecurityMultiTenancyRealmEvent.class,CompuwareSecurityPasswordPolicyEvent.class,CompuwareSecurityRoleEvent.class,CompuwareSecurityUserEvent.class})
public abstract class CompuwareSecurityUserInitiatedEvent extends CompuwareSecurityEvent {

    /* */
    private static final long serialVersionUID = 1L;
    
    /* */
    private String initiatingUsername;
                
    /* */
    private String originatingIpAddress;
    
    /* */
    private String originatingHostname;
    
    /**
     * 
     */
    protected CompuwareSecurityUserInitiatedEvent() {
        super();
    }

    /**
     * @param initiatingUsername
     * @param originatingIpAddress
     * @param originatingHostname
     * @param eventDetails
     * @param realmName
     */
    public CompuwareSecurityUserInitiatedEvent(
        String initiatingUsername,
        String originatingIpAddress,
        String originatingHostname,
        String eventDetails,
        String realmName) {
        
        super(eventDetails, realmName);
        
        if (initiatingUsername == null || initiatingUsername.equals("")) {
            throw new ServiceException("initiatingUsernamecannot be empty.");
        }
        this.initiatingUsername = initiatingUsername;
        
        if (originatingIpAddress == null || originatingIpAddress.equals("")) {
            throw new ServiceException("originatingIpAddress cannot be empty.");
        }
        this.originatingIpAddress = originatingIpAddress;
        
        if (originatingHostname == null || originatingHostname.equals("")) {
            throw new ServiceException("originatingHostname cannot be empty.");
        }
        this.originatingHostname = originatingHostname;
    }

    /**
     * @return the initiatingUsername
     */
    @XmlElement
    public final String getInitiatingUsername() {
        return initiatingUsername;
    }

    /**
     * @return the originatingIpAddress
     */
    @XmlElement
    public final String getOriginatingIpAddress() {
        return originatingIpAddress;
    }

    /**
     * @return the originatingHostname
     */
    @XmlElement
    public final String getOriginatingHostname() {
        return originatingHostname;
    }

    /**
     * @param initiatingUsername the initiatingUsername to set
     */
    protected final void setInitiatingUsername(String initiatingUsername) {
        this.initiatingUsername = initiatingUsername;
    }

    /**
     * @param originatingIpAddress the originatingIpAddress to set
     */
    protected final void setOriginatingIpAddress(String originatingIpAddress) {
        this.originatingIpAddress = originatingIpAddress;
    }

    /**
     * @param originatingHostname the originatingHostname to set
     */
    protected final void setOriginatingHostname(String originatingHostname) {
        this.originatingHostname = originatingHostname;
    }
    
   /*
    * (non-Javadoc)
    * @see java.lang.Object#toString()
    */
  public String toString() {
     
     StringBuilder sb = new StringBuilder();
     sb.append(this.getClass().getSimpleName());
     sb.append("{initiatingUsername: ");
     sb.append(this.initiatingUsername);
     sb.append(", ");
     sb.append("originatingIpAddress: ");
     sb.append(this.originatingIpAddress);
     sb.append(", ");
     sb.append("originatingHostname: ");
     sb.append(this.originatingHostname);
     sb.append(", ");
     super.toString(sb);
     sb.append("}");
     return sb.toString();
  }  
}