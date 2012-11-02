/*
* These materials contain confidential information and 
* trade secrets of Compuware Corporation. You shall 
* maintain the materials as confidential and shall not 
* disclose its contents to any third party except as may 
* be required by law or regulation. Use, disclosure, 
* or reproduction is prohibited without the prior express 
* written permission of Compuware Corporation.
* 
* All Compuware products listed within the materials are 
* trademarks of Compuware Corporation. All other company 
* or product names are trademarks of their respective owners.
* 
* Copyright (c) 2010 Compuware Corporation. All rights reserved.
* 
*/
package com.compuware.frameworks.security.persistence.dao.jdbc;

import com.compuware.frameworks.security.persistence.dao.IAclSql;

/**
 * @author dresser
 * @author tmyers
 */
public abstract class AclSql implements IAclSql {
	
	/* */
	protected static final String NOT_NULL = " not null, ";
	
	/* */
	protected static final String NOT_NULL_PRIMARY_KEY = " not null primary key, ";
	
	/**
	 * 
	 * @return String
	 */
	public final String getExternalCredentialCreateSql() {
		return "create table external_credential ( " +
				    "external_credential_id " + getIntegerType(false) + " " + this.getIdentityClause() + NOT_NULL +
				    "external_credential_domain  " + getVarCharType() + "(194) not null, " +
				    "external_credential_login   " + getVarCharType() + "(256) not null, " +
				    "external_credential_pw      " + getVarCharType() + "(1000) not null, " +
				    "external_credential_enabled " + getIntegerType(false) + " default 0, " +
				    "constraint external_credential_pk primary key(external_credential_domain, external_credential_login), " +
				    "constraint external_credential_uk1 unique(external_credential_id) " +
				    ")";
	}
	
	/**
	 * @return String 
	 */
	public final String getConfigurationCreateSql() {
		
		// With oracle the default keyword must follow the type.  i.e. not null default fails with syntax error.
		return "create table configuration ( " +
	    "configuration_id            " + this.getIntegerType(false) + NOT_NULL +
	    "configuration_name          " + getVarCharType() + "(100) default '' not null, " +
	    "configuration_version       " + getVarCharType() + "(100) default '' not null, " +
	    "constraint configuration_pk primary key (configuration_name, configuration_version), " +
	    "constraint configuration_uk1 unique(configuration_id) " +
	    ")";
	}
	
	/**
	 * 
	 * @return String
	 */
	public final String getInsertConfigurationSql() {
		return "insert into configuration (configuration_id, configuration_name, configuration_version) values (1, ?, ?)";
	}

	/**
	 * 
	 * @return String
	 */
	public final String getRetrieveConfigurationSql() {
		return "select configuration_name, configuration_version from configuration order by configuration_version";
	}
	
	/**
	 * 
	 * @return String
	 */
	public abstract String getIdentityClause();
	
	/**
	 * 
	 * @return String
	 */
	public abstract String getVarCharType();

	/**
	 * @return String
	 */
	public String getIntegerType(boolean bigIntger) {
		return "integer";
	}		
	
	/**
	 * 
	 * @return String
	 */
	public String getAclEntryCreateSql() {
		return "create table acl_entry ( " +
				  "id " + getIntegerType(true) + " " + this.getIdentityClause() + NOT_NULL_PRIMARY_KEY +
				  "acl_object_identity " + getIntegerType(true) + " not null, " + 
				  "ace_order " + getIntegerType(false) + " not null, " + 
				  "sid " + getIntegerType(true) + " not null, " +
				  "mask " + getIntegerType(false) + " not null, " +
				  "granting " + getIntegerType(false) + " not null, " +
				  "audit_success " + getIntegerType(false) + " not null, " +
				  "audit_failure " + getIntegerType(false) + " not null, " +
				  "constraint acl_entry_uk_1 unique(acl_object_identity,ace_order), " +
				  "constraint acl_entry_fk_1 foreign key(acl_object_identity) references acl_object_identity(id), " +
				  "constraint acl_entry_fk_2 foreign key(sid) references acl_sid(id) )";
	}
	
	/**
	 * 
	 * @return String
	 */
	public String getAclObjectIdentityCreateSql() {
		return "create table acl_object_identity ( " +
				  "id " + getIntegerType(true) + " " + this.getIdentityClause() + NOT_NULL_PRIMARY_KEY +
				  "object_id_class " + getIntegerType(true) + " not null, " +
				  "object_id_identity " + getIntegerType(false) + " not null, " +
				  "parent_object " + getIntegerType(true) + ", " +
				  "owner_sid " + getIntegerType(true) + ", " +
				  "entries_inheriting " + getIntegerType(false) + " not null, " + 
				  "constraint acl_object_identity_uk1 unique(object_id_class,object_id_identity), " + 
				  "constraint acl_object_identity_fk1 foreign key(parent_object)references acl_object_identity(id), " + 
				  "constraint acl_object_identity_fk_2 foreign key(object_id_class)references acl_class(id), " + 
				  "constraint acl_object_identity_fk_3 foreign key(owner_sid)references acl_sid(id) )";
	}

	public String getAclSidCreateSql() {
		return "create table acl_sid ( " +
				  "id " + getIntegerType(true) + " " + this.getIdentityClause() + NOT_NULL_PRIMARY_KEY +
				  "principal " + getIntegerType(false) + " not null, " +
				  "sid " + getVarCharType() + "(128) not null, " +
				  "constraint acl_sid_uk1 unique(sid,principal) )";
	}

	/**
	 * 
	 * @return String
	 */
	public String getAclClassCreateSql() {
		return "create table acl_class ( " +
				  "id " + getIntegerType(true) + " " + this.getIdentityClause() + NOT_NULL_PRIMARY_KEY +
				  "class " + getVarCharType() + "(256) not null, " +
				  "constraint acl_class_uk1 unique(class) )";
	}

    /**
     * 
     * @return String
     */
    public final String getAclClassIdentityQuery() {
    	return "select id from acl_class where class=?";    	
    }
    
    /**
     * 
     * @return String
     */
    public final String getAclSidIdentityQuery() {
    	return "select id from acl_sid where principal=? and sid=?";
    }

    /**
     * 
     * @return String
     */
    public String getInsertAclClass() {
    	return "insert into acl_class(class) values (?)";
    }
    
    /**
     * 
     * @return String
     */
    public String getInsertAclEntry() {
    	return "insert into acl_entry "
    	        + "(acl_object_identity, ace_order, sid, mask, granting, audit_success, audit_failure)"
    	        + "values (?, ?, ?, ?, ?, ?, ?)";
    }
    
    /**
     * 
     * @return String
     */
    public String getInsertAclObjectIdentity() {
    	return "insert into acl_object_identity "
    	        + "(object_id_class, object_id_identity, owner_sid, entries_inheriting) " + "values (?, ?, ?, ?)";
    }
    
    /**
     * 
     * @return String
     */
    public String getInsertAclSid() {
    	return "insert into acl_sid(principal, sid) values (?, ?)";
    }
}