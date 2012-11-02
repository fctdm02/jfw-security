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

import java.text.SimpleDateFormat;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
@XmlRootElement(name="migrationRecord")
public final class MigrationRecord extends DomainObject {

	/** */
	private static final long serialVersionUID = 1L;
	
	/** */
	public static final String USER = "User";

    /** */
    public static final String GROUP = "Group";
	
	/** */
	private Long migrationRecordId;
	
	/** */
	private String sourceRepositoryName;

    /** */
    private String principalType;
	
	/** */
	private String principalName;
	
	/** */
	private String nameValuePairs;
	
	/** Holds the "reason" why the given principal wasn't migrated. */
	private String reason;
	
    /** Holds the creation date (as a formatted String) */
    private String creationDate;
	
	/**
	 * Used to facilitate multi-tenancy. Each domain object must belong to a
	 * multi-tenancy "realm". If any unique constraints are created on 'name'
	 * fields, then those constraints need to incorporate the realm. e.g.
	 * 'principalName' on the 'SecurityPrincipal' table should have a unique
	 * index created that is a combination of principalName and the
	 * multiTenancyRealm foreign key.
	 */
	private MultiTenancyRealm multiTenancyRealm;

	/**
	 * 
	 */
	public MigrationRecord() {
	}

	/**
	 * 
	 * @param sourceRepositoryName
	 * @param principalType
	 * @param principalName
	 * @param nameValuePairs
	 * @param reason
	 * @param multiTenancyRealm
	 * @throws ValidationException 
	 */
	public MigrationRecord(
		String sourceRepositoryName,
		String principalType,
		String principalName, 
		String nameValuePairs,
		String reason,
		MultiTenancyRealm multiTenancyRealm) 
	throws 
		ValidationException {
		
		this.setSourceRepositoryName(sourceRepositoryName);
		this.setPrincipalType(principalType);
		this.setPrincipalName(principalName);
		this.setNameValuePairs(nameValuePairs);
		this.setReason(reason);
		
        java.util.Date date = new java.util.Date(System.currentTimeMillis());
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("H:mm:ss:SSS");
		
		this.setCreationDate(simpleDateFormat.format(date));
		this.setMultiTenancyRealm(multiTenancyRealm);
		
		validate();
	}
		
	/**
	 * @return the migrationRecordId
	 */
	@XmlAttribute
	public Long getMigrationRecordId() {
		return migrationRecordId;
	}

	/**
	 * @param migrationRecordId the migrationRecordId to set
	 */
	public void setMigrationRecordId(Long migrationRecordId) {
		this.migrationRecordId = migrationRecordId;
	}

	/**
	 * @return the sourceRepositoryName
	 */
	@XmlElement
	public String getSourceRepositoryName() {
	    return this.sourceRepositoryName;
	}

	/**
	 * @param sourceRepositoryName the sourceRepositoryName to set
	 */
	public void setSourceRepositoryName(String sourceRepositoryName) {
	    if (sourceRepositoryName != null && sourceRepositoryName.length() > 128) {
	        this.sourceRepositoryName = sourceRepositoryName.substring(0, 127);
	    } 
        this.sourceRepositoryName = sourceRepositoryName;
	}

    /**
     * @return the principalType
     */
    @XmlElement
    public String getPrincipalType() {
        return this.principalType;
    }

    /**
     * @param principalType the principalType to set
     */
    public void setPrincipalType(String principalType) {
        this.principalType = principalType;
    }
	
	/**
	 * @return the principalName
	 */
	@XmlElement
	public String getPrincipalName() {
	    return this.principalName;
	}

	/**
	 * @param principalName the principalName to set
	 */
	public void setPrincipalName(String principalName) {
	    this.principalName = DomainObject.trimString(principalName);
	}
	
	/**
	 * @return the nameValuePairs
	 */
	@XmlElement
	public String getNameValuePairs() {
	    return this.nameValuePairs;
	}

	/**
	 * @param nameValuePairs the nameValuePairs to set
	 */
	public void setNameValuePairs(String nameValuePairs) {
	    this.nameValuePairs = DomainObject.trimString(nameValuePairs);
	}

    /**
     * Holds the "reason" why the given principal wasn't migrated.
     * 
     * @return the reason
     */
	@XmlElement
    public String getReason() {
        return this.reason;
    }

    /**
     * Holds the "reason" why the given principal wasn't migrated.
     * 
     * @param reason the reason to set
     */
    public void setReason(String reason) {
        this.reason = DomainObject.setOptionalStringValue(reason);
    }
	
    /**
     * @return the creationDate
     */
    @XmlElement
    public String getCreationDate() {
        return creationDate;
    }

    /**
     * 
     */
    public void setCreationDate() {
        this.setCreationDate(System.currentTimeMillis());
    }
    
    /**
     * @param millis
     */
    public void setCreationDate(long millis) {
        java.util.Date date = new java.util.Date(millis);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("H:mm:ss:SSS");
        setCreationDate(simpleDateFormat.format(date));
    }
        
    /**
     * 
     * @param creationDate the creationDate to set
     */
    public void setCreationDate(String creationDate) {
        if (creationDate != null && creationDate.length() > 16) {
            this.creationDate = creationDate.substring(0, 16);
        } 
        this.creationDate = creationDate;
    }

	/**
	 * @return the multiTenancyRealm
	 */
    @XmlElement
	public MultiTenancyRealm getMultiTenancyRealm() {
		return multiTenancyRealm;
	}

	/**
	 * @param multiTenancyRealm the multiTenancyRealm to set
	 */
	public void setMultiTenancyRealm(MultiTenancyRealm multiTenancyRealm) {
		this.multiTenancyRealm = multiTenancyRealm;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.DomainObject#getPersistentIdentity()
	 */
	public Long getPersistentIdentity() {
		
		return this.getMigrationRecordId();
	}
	
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.model.DomainObject#getNaturalIdentity()
    */   
   public String getNaturalIdentity() {
	   
		StringBuilder sb = new StringBuilder();
		
		sb.append(this.getMultiTenancyRealm().getRealmName());
		sb.append(NATURAL_IDENTITY_DELIMITER);
		sb.append(this.getSourceRepositoryName());
        sb.append(NATURAL_IDENTITY_DELIMITER);
        sb.append(this.getPrincipalType());
		sb.append(NATURAL_IDENTITY_DELIMITER);
		sb.append(this.getPrincipalName());
        sb.append(NATURAL_IDENTITY_DELIMITER);
        sb.append(this.getCreationDate());
        sb.append(NATURAL_IDENTITY_DELIMITER);
        sb.append(this.getReason());        
		return sb.toString();
   }
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.service.api.model.DomainObject#validate()
	 */
	public void validate() throws ValidationException {
				
		if (this.multiTenancyRealm == null) {
		    throw new ValidationException(ValidationException.FIELD_MULTI_TENANCY_REALM, ValidationException.REASON_CANNOT_BE_NULL);	
		}
		
		if (this.getSourceRepositoryName() == null || this.getSourceRepositoryName().isEmpty()) {
			throw new ValidationException(ValidationException.FIELD_SOURCE_REPOSITORY_NAME, ValidationException.REASON_CANNOT_BE_EMPTY);
		}
		
        if (this.getPrincipalType() == null) {
            throw new ValidationException(ValidationException.FIELD_PRINCIPAL_TYPE, ValidationException.REASON_CANNOT_BE_NULL); 
        }

        if (this.getPrincipalType() == null) {
            throw new ValidationException(ValidationException.FIELD_PRINCIPAL_NAME, ValidationException.REASON_CANNOT_BE_NULL); 
        }
        
        if (!this.getPrincipalType().equals(USER) && !this.getPrincipalType().equals(GROUP)) {
            String reason = ValidationException.REASON_INVALID_ENUMERATED_VALUE;
            reason = reason.replace(ValidationException.TOKEN_ZERO, this.getPrincipalType());
            reason = reason.replace(ValidationException.TOKEN_ONE, USER + "," + GROUP);
            throw new ValidationException(ValidationException.FIELD_PRINCIPAL_TYPE,    "'principalType' field must be either: [" + USER + "] or [" + GROUP + "].");
        }
		
		if (this.getPrincipalName() == null) {
		    throw new ValidationException(ValidationException.FIELD_PRINCIPAL_NAME, ValidationException.REASON_CANNOT_BE_NULL);	
		}
		
        if (this.getNameValuePairs() == null) {
            throw new ValidationException(ValidationException.FIELD_NAME_VALUE_PAIRS, ValidationException.REASON_CANNOT_BE_NULL); 
        }

        if (this.getReason() == null) {
            throw new ValidationException(ValidationException.FIELD_REASON, ValidationException.REASON_CANNOT_BE_NULL); 
        }
        
        if (this.getCreationDate() == null) {
            throw new ValidationException(ValidationException.FIELD_CREATION_DATE, ValidationException.REASON_CANNOT_BE_NULL); 
        }
	}
	
	/*
	 * (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		
		return this.getNaturalIdentity();
	}
}