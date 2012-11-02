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

import com.compuware.frameworks.security.service.api.authorization.IAclDomainObject;
import com.compuware.frameworks.security.service.api.model.exception.ValidationException;

/**
 * 
 * @author tmyers
 * 
 */
public abstract class DomainObject implements Comparable<DomainObject>, IAclDomainObject, Serializable {

	/* */
	private static final long serialVersionUID = 1L;

	/** */
	public static final String NATURAL_IDENTITY_DELIMITER = " ";
	
	/** */
	public static final int MAX_STRING_LENGTH = 256;
	
	/** */
	public static final String ORACLE_EMPTY_STRING_ID = "4121739f-b4c5-4353-a3ad-f2e538f1ac0d";
	
	/* */
	private static final String EVERYONE_GROUP = "everyone";

	/* */
	private Integer version;
	
	/* */
	private boolean isDeletable = true; 

    /* */
    private boolean isModifiable = true; 
	
	/**
	 * 
	 */
	public DomainObject() {
	}
	
	/**
	 * 
	 * @return version
	 */
	public final Integer getVersion() {
		return this.version;
	}
	
	/**
	 * 
	 * @param version
	 */
	public final void setVersion(Integer version) {
		this.version = version;
	}

    /**
     * 
     * @return isDeletable
     */
    public final boolean getIsDeletable() {
        if (getClass().equals(SecurityGroup.class) && getNaturalIdentity().equals(EVERYONE_GROUP)) {
            return false;
        }
        return this.isDeletable;
    }
    
    /**
     * 
     * @param isDeletable
     */
    public final void setIsDeletable(boolean isDeletable) {
        this.isDeletable = isDeletable;
    }

    /**
     * 
     * @return isModifiable
     */
    public final boolean getIsModifiable() {
        if (getClass().equals(SecurityGroup.class) && getNaturalIdentity().equals(EVERYONE_GROUP)) {
            return false;
        }
        return this.isModifiable;
    }
    
    /**
     * 
     * @param isModifiable
     */
    public final void setIsModifiable(boolean isModifiable) {
        this.isModifiable = isModifiable;
    }
    
	/**
     * From a logical perspective, the <code>persistent identity</code> of a domain 
     * object is equivalent to the notion of "object identity" in that this attribute 
     * serves to uniquely identify a domain object, except that when its value is
     * <code>null</code>, the domain object has no persistent state (yet).  In 
     * hibernate parlance, this means that the object is in a "transient" state.
     * <p>
	 * 
	 * @return The persisted identifier for this instance
	 */
	public abstract Long getPersistentIdentity();
	
	/**
     * When the persistent identity is null, then the domain object can be uniquely 
     * identified by its <code>natural identity</code>.  <code>equals</code>, 
     * <code>hashCode</code> and <code>Comparable</code> use the object identity if
     * non-null, and natural identity otherwise.
	 * 
	 * @return The instance's natural identity (independent of its persistent identity) 
	 */
	public abstract String getNaturalIdentity();
	
	/**
	 * Used by the domain object factory and various update methods on the 
	 * <code>IManagementService</code> interface to ensure that a domain object
	 * is in a valid state for creation and/or updating.
	 * 
	 * @throws ValidationException
	 */
	public abstract void validate() throws ValidationException; 
	
	/**
	 * 
	 * @return
	 */
	public static String XgetEmptyStringIdentity() {
	    return DomainObject.ORACLE_EMPTY_STRING_ID;
	}
	
    /** 
     *  This is necessary because Oracle treats an empty string as null
     *  
     *  @param string A string that could be empty.  If so, a special value used to 
     *  denote this (to accommodate Oracle)
     *  
     *  @return The "user-friendly" value of the optional string field.  
     *  That is, if empty, an empty string is returned.
     *  <p>
     *  It is expected that domain object getters use this method. 
     */
    public static String getOptionalStringValue(final String string) {
        
        String returnValue = null;
        if (string == null || string.equals(ORACLE_EMPTY_STRING_ID)) {
            returnValue = "";
        } else {
            returnValue = string;
        }
        return returnValue;
    }
	
    /** 
     *  This is necessary because Oracle treats an empty string as null
     *  
     *  @param string A string that could be empty.  If so, a special value used to 
     *  denote this (to accommodate Oracle)
     *  
     *  @return The "database-facing" value of the optional string field.  
     *  That is, if empty, the Oracle empty string identifier is returned
     *  <p>
     *  It is expected that domain object setters use this method (for optional string fields).
     *  @see trimString() 
     */
    public static String setOptionalStringValue(final String string) {
        
        String returnValue = null;
        if (string == null || string.trim().length() == 0) {
            returnValue = ORACLE_EMPTY_STRING_ID;
        } else {
            returnValue = trimString(string);
        }
        
        return returnValue;
    }
    
    /**
     * The length of the string is trimmed at <code>MAX_STRING_LENGTH</code> 
     * characters.  It is expected that domain object setters use this method 
     * for required string fields.
     * 
     * @param string
     * @return
     */
    public static String trimString(final String string) {
        
        String returnValue = string;
        if (returnValue != null) {
            returnValue = returnValue.trim();
            if (returnValue.length() >= MAX_STRING_LENGTH) {
                returnValue = returnValue.substring(0, MAX_STRING_LENGTH-1);
            }
        }
        return returnValue;
    }
	
   /*
    * (non-Javadoc)
    * @see java.lang.Object#hashCode()
    */
   public final int hashCode() {
       
      if (this.getPersistentIdentity() != null) {
          return this.getPersistentIdentity().hashCode();  
      }        
      
      return this.getNaturalIdentity().hashCode();
   }
	
   /*
    * (non-Javadoc)
    * @see java.lang.Comparable#compareTo(java.lang.Object)
    */
   public final int compareTo(DomainObject that) {
      
        if (this.getPersistentIdentity() != null && that instanceof DomainObject && ((DomainObject)that).getPersistentIdentity() != null) {
            return this.getPersistentIdentity().compareTo(((DomainObject)that).getPersistentIdentity());
        }
        
        return this.getNaturalIdentity().compareTo(((DomainObject)that).getNaturalIdentity());
   }
   
   /*
    * (non-Javadoc)
    * @see java.lang.Object#equals(java.lang.Object)
    */
   public final boolean equals(Object that) {
      
      if (this.getPersistentIdentity() != null && that instanceof DomainObject && ((DomainObject)that).getPersistentIdentity() != null) {
    	  
    	  return this.getPersistentIdentity().equals(((DomainObject)that).getPersistentIdentity());
    	  
      } else if (this.getPersistentIdentity() != null && that instanceof Long) {
    	  
    	  return this.getPersistentIdentity().equals(that);

      }
      
      return this.getNaturalIdentity().equals(((DomainObject)that).getNaturalIdentity());
   }
   
   /*
    * (non-Javadoc)
    * @see com.compuware.frameworks.security.service.api.authorization.IAclDomainObject#getId()
    */
   public long getId() {
	   return this.getPersistentIdentity().longValue();
   }
}