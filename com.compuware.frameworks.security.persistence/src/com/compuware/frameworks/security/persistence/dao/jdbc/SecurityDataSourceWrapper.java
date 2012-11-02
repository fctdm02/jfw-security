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

import java.sql.Connection;
import java.sql.SQLException;

import javax.sql.DataSource;

import org.apache.log4j.Logger;

/**
 * @author tmyers
 */
public class SecurityDataSourceWrapper implements ISecurityDataSourceWrapper, DataSource {
    
    /* */
    private final Logger logger = Logger.getLogger(SecurityDataSourceWrapper.class);
    
    /* */
    private DataSource dataSource;
    
    /**
     * 
     * @param dataSource
     */
    public SecurityDataSourceWrapper(DataSource dataSource) {
        setDataSource(dataSource);
    }
    
    /**
     * 
     * @return DataSource
     */
    public final DataSource getDataSource() {
        return this.dataSource;
    }
    
    /**
     * 
     * @param dataSource
     */
    public final void setDataSource(DataSource dataSource) {
        logger.info("Setting JDBC DataSource...");
        this.dataSource = dataSource;
    }
    
    /*
     * (non-Javadoc)
     * @see javax.sql.DataSource#getConnection()
     */
    public final Connection getConnection() throws SQLException {
        return this.dataSource.getConnection();
    }
        
    /*
     * (non-Javadoc)
     * @see javax.sql.DataSource#getConnection(java.lang.String, java.lang.String)
     */
    public final Connection getConnection(String username, String password) throws SQLException {
        return this.dataSource.getConnection(username, password);
    }
    
    /*
     * (non-Javadoc)
     * @see javax.sql.CommonDataSource#getLogWriter()
     */
    public final java.io.PrintWriter getLogWriter() throws SQLException {
        return this.dataSource.getLogWriter();
    }

    /*
     * (non-Javadoc)
     * @see javax.sql.CommonDataSource#setLogWriter(java.io.PrintWriter)
     */
    public final void setLogWriter(java.io.PrintWriter out) throws SQLException {
        this.dataSource.setLogWriter(out);
    }

    /*
     * (non-Javadoc)
     * @see javax.sql.CommonDataSource#setLoginTimeout(int)
     */
    public final void setLoginTimeout(int seconds) throws SQLException {
        this.setLoginTimeout(seconds);
    }

    /*
     * (non-Javadoc)
     * @see javax.sql.CommonDataSource#getLoginTimeout()
     */
    public final int getLoginTimeout() throws SQLException {
        return this.dataSource.getLoginTimeout();
    }

    /*
     * (non-Javadoc)
     * @see java.sql.Wrapper#unwrap(java.lang.Class)
     */
    public final <T> T unwrap(java.lang.Class<T> iface) throws java.sql.SQLException {
        return this.dataSource.unwrap(iface);
    }

    /*
     * (non-Javadoc)
     * @see java.sql.Wrapper#isWrapperFor(java.lang.Class)
     */
    public final boolean isWrapperFor(java.lang.Class<?> iface) throws java.sql.SQLException {
        return this.dataSource.isWrapperFor(iface);
    }
}