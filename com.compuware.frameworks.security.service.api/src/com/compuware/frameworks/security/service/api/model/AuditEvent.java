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

import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
@XmlRootElement
public final class AuditEvent extends DomainObject {

	/** */
	private static final long serialVersionUID = 1L;
	
	
	/** */
	private Long auditEventId;

	/** */
	private String initiatingUsername;
	
	/** */
	private String eventDetails;
	
	/** */
	private String originatingIpAddress;

	/** */
	private String originatingHostname;
	
	/** */
	private java.util.Date eventDate;

	/** 
	 * Used to facilitate multi-tenancy.  Each domain object must belong to a multi-tenancy "realm".  If any unique constraints are
	 * created on 'name' fields, then those constraints need to incorporate the realm.  e.g. 'principalName' on the 'SecurityPrincipal' table
	 * should have a unique index created that is a combination of principalName and the multiTenancyRealm foreign key.
	 */
	private String realmName;
    
    /*
     * 
     */
	@SuppressWarnings("unused")
    private AuditEvent() {
        setIsDeletable(false);
        setIsModifiable(false);
    }

    /**
     * Once an audit event has been persisted, it cannot be changed or deleted. 
     * (In fact, no methods exist in the DAO with which to do updates/deletes, 
     * but setting the attributes below is done for semantic consistency)
     * 
     * @param initiatingUsername
     * @param eventDetails
     * @param originatingIpAddress
     * @param originatingHostname
     * @param eventDate
     * @param realmName
     */
	public AuditEvent(
	    String initiatingUsername,
	    String eventDetails,
	    String originatingIpAddress,
	    String originatingHostname,
	    java.util.Date eventDate,
	    String realmName) {
	    setIsDeletable(false);
	    setIsModifiable(false);
	    this.setInitiatingUsername(initiatingUsername);
	    this.setEventDetails(eventDetails);
	    this.setOriginatingIpAddress(originatingIpAddress);
	    this.setOriginatingHostname(originatingHostname);
	    this.setEventDate(eventDate);
	    this.setRealmName(realmName);
	}

   /**
    * @return the auditEventId
    */
   @XmlAttribute
   public Long getAuditEventId() {
      return auditEventId;
   }

   /**
    * @param auditEventId the auditEventId to set
    */
   public void setAuditEventId(Long auditEventId) {
      this.auditEventId = auditEventId;
   }
	
	/**
	 * @return the eventDetails
	 */
   @XmlAttribute
	public String getEventDetails() {
        return this.eventDetails;
	}

	/**
	 * @param eventDetails the eventDetails to set
	 */
	public void setEventDetails(String eventDetails) {
	    this.eventDetails = DomainObject.trimString(eventDetails);
	}

	/**
	 * @return the originatingIpAddress
	 */
	@XmlAttribute
	public String getOriginatingIpAddress() {
	    return this.originatingIpAddress;
	}

	/**
	 * @param originatingIpAddress the originatingIpAddress to set
	 */
	public void setOriginatingIpAddress(String originatingIpAddress) {
	    this.originatingIpAddress = originatingIpAddress;
	}

	/**
	 * @return the originatingHostname
	 */
	@XmlAttribute
	public String getOriginatingHostname() {
	    return this.originatingHostname;
	}

	/**
	 * @param originatingHostname the originatingHostname to set
	 */
	public void setOriginatingHostname(String originatingHostname) {
	    this.originatingHostname = originatingHostname;
	}

	/**
	 * @return the initiatingUsername
	 */
	@XmlAttribute
	public String getInitiatingUsername() {
	    return this.initiatingUsername;
	}

	/**
	 * @param initiatingUsername the initiatingUsername to set
	 */
	public void setInitiatingUsername(String initiatingUsername) {
	    this.initiatingUsername = initiatingUsername;
	}
 
	/**
	 * @return the eventDate
	 */
	@XmlAttribute
	public java.util.Date getEventDate() {
		return eventDate;
	}

	/**
	 * @param eventDate the eventDate to set
	 */
	public void setEventDate(java.util.Date eventDate) {
		this.eventDate = eventDate;
	}
	
	/**
	 * @return the realmName
	 */
	@XmlAttribute
	public String getRealmName() {
	    return this.realmName;
	}

	/**
	 * @param realmName the realmName to set
	 */
	public void setRealmName(String realmName) {
	    this.realmName = realmName;
	}

	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getPersistentIdentity()
    */
   public Long getPersistentIdentity() {
	   
      return getAuditEventId();
   }

   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getNaturalIdentity()
    */
   public String getNaturalIdentity() {
	   
	   StringBuilder sb = new StringBuilder();
       sb.append(getInitiatingUsername());
       sb.append(NATURAL_IDENTITY_DELIMITER);
       sb.append(getEventDetails());     
       sb.append(NATURAL_IDENTITY_DELIMITER);
       sb.append(getOriginatingIpAddress());     
       sb.append(NATURAL_IDENTITY_DELIMITER);
       sb.append(getOriginatingHostname());     
       sb.append(NATURAL_IDENTITY_DELIMITER);
	   sb.append(getEventDate());
	   sb.append(NATURAL_IDENTITY_DELIMITER);
	   sb.append(getRealmName());
	   return sb.toString();
   }
    
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.DomainObject#validate()
	 */
	public void validate() throws ValidationException {

		if (getInitiatingUsername() == null || getInitiatingUsername().isEmpty()) {
			throw new ValidationException(ValidationException.FIELD_USERNAME, ValidationException.REASON_CANNOT_BE_EMPTY);	
		}

		if (getEventDetails() == null || getEventDetails().isEmpty()) {
		    throw new ValidationException(ValidationException.FIELD_EVENT_DETAILS, ValidationException.REASON_CANNOT_BE_EMPTY);
		}

		if (getOriginatingIpAddress() == null || getOriginatingIpAddress().isEmpty()) {
		    throw new ValidationException(ValidationException.FIELD_IP_ADDRESS, ValidationException.REASON_CANNOT_BE_EMPTY);
		}

		if (getOriginatingHostname() == null || getOriginatingHostname().isEmpty()) {
		    throw new ValidationException(ValidationException.FIELD_HOST_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
		}

		if (getEventDate() == null) {
		    throw new ValidationException(ValidationException.FIELD_EVENT_DATE, ValidationException.REASON_CANNOT_BE_EMPTY);
		}
		
		if (getRealmName() == null || getRealmName().isEmpty()) {
		    throw new ValidationException(ValidationException.FIELD_REALM_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
		}
	}
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#toString()
    */
   public String toString() {
	   
	  return getNaturalIdentity();
   }
}