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

/**
 * 
 * @author dresser
 * @author tmyers
 */
public final class OracleAclSql extends AclSql {

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.jdbc.AclSql#getIdentityClause()
     */
    public final String getIdentityClause() {
    	// For Oracle return empty string.  We will have to use a sequence in the
    	// insert statement.  
        return "";
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.jdbc.AclSql#getVarCharType()
     */
    public final String getVarCharType() {
        return "nvarchar2";
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.jdbc.AclSql#getVarCharType()
     */
    public final String getIntegerType(boolean bigInteger) {
    	
    	if (bigInteger) {
    		return "number(38)";
    	} else {
    		return "number(10)";
    	}
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.IAclSql#getDeleteOldAuditEventSql()
     */
    public final String getDeleteOldAuditEventSql() {
        return "DELETE FROM AUDIT_EVENT WHERE EVENT_DATE < TO_TIMESTAMP('{0}', 'YYYY-MM-DD')";
    }    
	
	/**
	 * 
	 * @return String
	 */
	public String getAclEntryCreateSql() {
		return "begin " +
					"execute immediate 'create sequence acl_entry_sequence minvalue 1 start with 1 increment by 1 cache 20'; " +
					"execute immediate 'create table acl_entry ( " +
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
					  "constraint acl_entry_fk_2 foreign key(sid) references acl_sid(id) )'; " +
			    "end;"  ;
	}
	
	/**
	 * 
	 * @return String
	 */
	public String getAclObjectIdentityCreateSql() {
		return "begin " +
				"execute immediate 'create sequence acl_object_identity_sequence minvalue 1 start with 1 increment by 1 cache 20'; " +
				"execute immediate 'create table acl_object_identity ( " +
				  "id " + getIntegerType(true) + " " + this.getIdentityClause() + NOT_NULL_PRIMARY_KEY +
				  "object_id_class " + getIntegerType(true) + " not null, " +
				  "object_id_identity " + getIntegerType(false) + " not null, " +
				  "parent_object " + getIntegerType(true) + ", " +
				  "owner_sid " + getIntegerType(true) + ", " +
				  "entries_inheriting " + getIntegerType(false) + " not null, " + 
				  "constraint acl_object_identity_uk1 unique(object_id_class,object_id_identity), " + 
				  "constraint acl_object_identity_fk1 foreign key(parent_object)references acl_object_identity(id), " + 
				  "constraint acl_object_identity_fk_2 foreign key(object_id_class)references acl_class(id), " + 
				  "constraint acl_object_identity_fk_3 foreign key(owner_sid)references acl_sid(id) )'; " +
	    		"end;"  ;
	}

	public String getAclSidCreateSql() {
		return "begin " +
					"execute immediate 'create sequence acl_sid_sequence minvalue 1 start with 1 increment by 1 cache 20'; " +
					"execute immediate 'create table acl_sid ( " +
					  "id " + getIntegerType(true) + " " + this.getIdentityClause() + NOT_NULL_PRIMARY_KEY +
					  "principal " + getIntegerType(false) + " not null, " +
					  "sid " + getVarCharType() + "(128) not null, " +
					  "constraint acl_sid_uk1 unique(sid,principal) )'; " +
	    		"end;"  ;
	}

	/**
	 * 
	 * @return String
	 */
	public String getAclClassCreateSql() {
		return "begin " +
					"execute immediate 'create sequence acl_class_sequence minvalue 1 start with 1 increment by 1 cache 20'; " +
					"execute immediate 'create table acl_class ( " +
					  "id " + getIntegerType(true) + " " + this.getIdentityClause() + NOT_NULL_PRIMARY_KEY +
					  "class " + getVarCharType() + "(256) not null, " +
					  "constraint acl_class_uk1 unique(class) )'; " +
	    		"end;"  ;
	}

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.jdbc.AclSql#getInsertAclClass()
     */
    public final String getInsertAclClass() {
    	return "insert into acl_class(id, class) values (acl_class_sequence.NEXTVAL, ?)";
    }
    
    /**
     * 
     * @return String
     */
    public String getInsertAclEntry() {
    	return "insert into acl_entry "
    	        + "(id, acl_object_identity, ace_order, sid, mask, granting, audit_success, audit_failure)"
    	        + "values (acl_entry_sequence.NEXTVAL, ?, ?, ?, ?, ?, ?, ?)";
    }
    
    /**
     * 
     * @return String
     */
    public String getInsertAclObjectIdentity() {
    	return "insert into acl_object_identity "
    	        + "(id, object_id_class, object_id_identity, owner_sid, entries_inheriting) " + 
    			"values (acl_object_identity_sequence.NEXTVAL, ?, ?, ?, ?)";
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.jdbc.AclSql#getInsertAclSid()
     */
    public final String getInsertAclSid() {
    	return "insert into acl_sid(id, principal, sid) values (acl_sid_sequence.NEXTVAL, ?, ?)";
    }
}