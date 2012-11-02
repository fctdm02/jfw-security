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
public final class SqlServerAclSql extends AclSql {

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.jdbc.AclSql#getIdentityClause()
     */
	public String getIdentityClause() {
		return "identity(100, 1)";
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.dao.jdbc.AclSql#getVarCharType()
	 */
	public String getVarCharType() {
		return "nvarchar";
	}

	/**
	 * @return String
	 */
	public String getIntegerType(boolean bigInteger) {
		if (bigInteger) {
			return "bigint";
		} else {
			return "integer";
		}
	}		
	
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.persistence.dao.IAclSql#getDeleteOldAuditEventSql()
     */
    public String getDeleteOldAuditEventSql() {
        return "DELETE FROM AUDIT_EVENT WHERE EVENT_DATE < CAST('{0}' AS datetime)";
    }
	
}