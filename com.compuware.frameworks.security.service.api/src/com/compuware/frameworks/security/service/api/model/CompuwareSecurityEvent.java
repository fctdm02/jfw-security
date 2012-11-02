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
import java.util.Date;

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
@XmlSeeAlso({CompuwareSecuritySessionEvent.class,CompuwareSecurityUserInitiatedEvent.class})
public abstract class CompuwareSecurityEvent implements Serializable {

    /* */
    private static final long serialVersionUID = 1L;
    
    /* */
    private String eventDetails;
            
    /* */
    private String realmName;
    
    /* */
    private long eventAge;
       
	/**
	 * 
	 */
	protected CompuwareSecurityEvent() {
	}

	/**
	 * 
	 * @param eventDetails
	 * @param realmName
	 */
	public CompuwareSecurityEvent(
	    String eventDetails,
	    String realmName) {

        if (eventDetails == null || eventDetails.trim().equals("")) {
            this.eventDetails = this.getClass().getSimpleName();
        } else {
            this.eventDetails = eventDetails;    
        }
	    	    	    	    
	    if (realmName == null || realmName.equals("")) {
	        throw new ServiceException("realmName cannot be empty.");
	    }
	    this.realmName = realmName;
	    
	    this.eventAge = System.currentTimeMillis();
	}

    /**
     * @return the eventDetails
     */
	@XmlElement
    public final String getEventDetails() {
        return this.eventDetails;
    }

    /**
     * @return the realmName
     */
	@XmlElement
    public final String getRealmName() {
        return this.realmName;
    }

    /**
     * @return the eventAge
     */
	@XmlElement
    public final long getEventAge() {
        return this.eventAge;
    }
 
    /**
     * @param eventDetails the eventDetails to set
     */
    protected final void setEventDetails(String eventDetails) {
        this.eventDetails = eventDetails;
    }

    /**
     * @param realmName the realmName to set
     */
    protected final void setRealmName(String realmName) {
        this.realmName = realmName;
    }

    /**
     * @param eventAge the eventAge to set
     */
    protected final void setEventAge(long eventAge) {
        this.eventAge = eventAge;
    }
	
    /**
     * 
     * @param sb
     */
   protected void toString(StringBuilder sb) {
      
      sb.append("eventDetails: ");
      sb.append(this.eventDetails);
      sb.append(", ");
      sb.append("realmName: ");
      sb.append(", ");
      sb.append("eventDate: ");
      sb.append(new Date(this.eventAge));
      sb.append(", ");
      sb.append(this.realmName);
   }
   
   /*
    * (non-Javadoc)
    * @see java.lang.Object#toString()
    */
  public String toString() {
     
     StringBuilder sb = new StringBuilder();
     sb.append(this.getClass().getSimpleName());
     sb.append("{");
     this.toString(sb);
     sb.append("}");
     return sb.toString();
  }   
}