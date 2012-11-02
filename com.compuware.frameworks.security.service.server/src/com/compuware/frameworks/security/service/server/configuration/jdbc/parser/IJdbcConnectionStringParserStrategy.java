/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product names are trademarks of their respective owners.
 * 
 * Copyright 2011 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.server.configuration.jdbc.parser;


/**
 * <h1>JDBC Connection String Syntax:</h1>
 * 
 * <a href="http://jtds.sourceforge.net/faq.html#driverImplementation">SQLServer - JTDS</a>:<br>
 * <code>
 *    jdbc:jtds:<server_type>://<server>[:<port>][/<database>][;<property>=<value>[;...]]
 * </code>
 * </p>
 * 
 * <a href="http://www.orafaq.com/wiki/JDBC">Oracle</a>:<br>
 * <code>
 *    jdbc:oracle:thin:@//[HOST][:PORT]/SERVICE
 * </code> <b>(new syntax)</b><br>
 * <code>
 *    jdbc:oracle:thin:@[HOST][:PORT]:SID
 * </code> <b>(old syntax)</b>
 * </p>
 * 
 * <a href="http://db.apache.org/derby/manuals/develop/develop26.html">Apache Derby</a>:<br>
 * <code>
 *    jdbc:derby:[subsubprotocol:][databaseName][;attribute=value]
 * </code>
 * <p/>
 * 
 * @author tmyers
 */
public interface IJdbcConnectionStringParserStrategy {
    
    /**
     * @return either DERBY, SQLSERVER or ORACLE 
     */
    String getDatabaseType();
    
    /**
     * @return the <code>hostname</code>.
     */
    String getHostname();
    
    /**
     * @return the <code>port</code>.
     */
    String getPort();
    
    /**
     * @return the <code>databaseName</code>.
     */
    String getDatabaseName();
    
    /**
     * @return an authentication type constant for the currently set JDBC connection string.
     * <p>
     * For non-windows/non-SQL Server the only choice is LOCAL_DB_AUTH_TYPE.  For windows, two additional
     * choices are: WINDOWS_DOMAIN_SQL_SERVER_AUTH_TYPE and INTEGRATED_SECURITY_SQL_SERVER_AUTH_TYPE
     */
    String getDbAuthType();

    /**
     *@return If WINDOWS_INTEGRATED_SECURITY_DB_AUTH_TYPE is used for the DB auth type, then the given
     *username/password will be authenticated against the windows domain specified by this field. 
     */
    String getWindowsDomain();
    
    /**
     * @return Any additional name=value pairs that are appended to the end of the connection string as
     * returned by calling <code>parseAdditionalConnectionStringProperties()</code> for the currently set
     * JDBC connection string.
     */
    String getAdditionalConnectionStringProperties();
}
