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
package com.compuware.frameworks.security.persistence;

import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.sql.DataSource;

import org.apache.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.orm.hibernate3.LocalSessionFactoryBean;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.ResourceTransactionManager;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import com.compuware.frameworks.persistence.core.hibernate.ComboPooledDataSourceFactoryBean;
import com.compuware.frameworks.security.api.configuration.ICompuwareSecurityJdbcConfiguration;
import com.compuware.frameworks.security.persistence.dao.IAclSql;
import com.compuware.frameworks.security.persistence.dao.IAuditEventDao;
import com.compuware.frameworks.security.persistence.dao.IMigrationRecordDao;
import com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao;
import com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao;
import com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao;
import com.compuware.frameworks.security.persistence.dao.jdbc.ISecurityDataSourceWrapper;
import com.compuware.frameworks.security.service.api.authentication.exception.InvalidCredentialsException;
import com.compuware.frameworks.security.service.api.exception.InvalidConnectionException;

/**
 * Bootstrap bean class for JFW-Security "persistence" bundle.  This is used for clients that want to access services via the 
 * singleton instance here, that is accessible outside of Spring via the <code>ServiceProvider.getInstance()</code>                                                     
 * call. It is preferred, however, that clients use the Spring/OSGi approach            
 * (i.e. import the Spring beans as OSGi "services" that are exported here:<br>
 * <ul>             
 *   <li><b>OSGi Service ID</b> (DAO Interface)
 *   <li>-----------------------------------------------    
 *   <li><b>auditEventDao</b> (com.compuware.frameworks.security.persistence.dao.IAuditEventDao)                            
 *   <li><b>multiTenancyRealmDao</b> (com.compuware.frameworks.security.persistence.dao.IMultiTenancyRealmDao)
 *   <li><b>passwordDao</b> (com.compuware.frameworks.security.persistence.dao.IPasswordDao)
 *   <li><b>passwordPolicyDao</b> (com.compuware.frameworks.security.persistence.dao.IPasswordPolicyDao)
 *   <li><b>securityPrincipalDao</b> (com.compuware.frameworks.security.persistence.dao.ISecurityPrincipalDao)
 *   <li><b>securityRoleDao</b> (com.compuware.frameworks.security.persistence.dao.ISecurityRoleDao)
 * </ul>                                                                                    
 * @author tmyers
 * 
 */
public class PersistenceProvider implements IPersistenceProvider, ApplicationContextAware {
	
    
    /** */
    public static final int MAX_WAIT_IN_SECONDS = 1;
    
    /** */
    public static final int WAIT_INTERVAL_IN_MILLIS = 1000;
    
	/* */
	private static final Logger LOGGER = Logger.getLogger(PersistenceProvider.class);
			
	/* */
	private static AbstractApplicationContext applicationContext;
	
	/* */
	private static boolean isRefreshing;
	
	/* */
	private static String schemaVersion;
	
	/**
	 * 
	 * @return
	 * @throws InterruptedException 
	 */
	public static IPersistenceProvider getInstance() throws InterruptedException {
		
        if (applicationContext == null) {
            int i = 0;
            while (applicationContext == null && i < MAX_WAIT_IN_SECONDS) {
                i = i + 1;
                LOGGER.debug("Waiting for Compuware Security PersistenceProvider to be initialized...");
                Thread.sleep(WAIT_INTERVAL_IN_MILLIS);
            }
        }
        if (applicationContext == null) {
            throw new RuntimeException("Compuware Security PersistenceProvider timed out waiting for application context to be initialized...");
        }
		return (IPersistenceProvider)applicationContext.getBean("persistenceProvider");	
	}
			
	/**
	 * 
	 */
	public PersistenceProvider() {		
	}

	/*
	 * (non-Javadoc)
	 * @see org.springframework.context.ApplicationContextAware#setApplicationContext(org.springframework.context.ApplicationContext)
	 */
	public synchronized final void setApplicationContext(ApplicationContext applicationContextParameter) throws BeansException {
		applicationContext = (AbstractApplicationContext)applicationContextParameter;
		LOGGER.info("Bundle version: " + this.getBundleVersion());
		LOGGER.info("Schema version: " + this.getSchemaVersion());
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#getSchemaVersion()
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public final String getSchemaVersion() {
		
		// If we need to, create the JDBC-accessed (i.e. Non hibernate controlled tables)
		final IAclSql sql = this.getAclSql();
		final DataSource dataSource = this.getSecurityDataSourceWrapper().getDataSource(); 
		final JdbcTemplate jdbcTemplate = getJdbcTemplate();
		final TransactionTemplate transactionTemplate = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        transactionTemplate.execute(new TransactionCallback() {
            public Object doInTransaction(TransactionStatus arg0) {
            	try {
            		
            		try {

                    	List<?> list = getJdbcTemplate().queryForList(sql.getRetrieveConfigurationSql());
                		Map<?,?> listMap = (Map<?,?>)list.get(0);
                		schemaVersion = (String)listMap.get("CONFIGURATION_VERSION");
            			LOGGER.info("Compuware Security: Schema version: " + schemaVersion);
            			LOGGER.info("Compuware Security: Bundle version: " + Activator.getBundleVersion());
            			if (!schemaVersion.equals(Activator.getBundleVersion())) {
            			    
            				LOGGER.info("Compuware Security: Schema version does not match bundle version...");
            				// TDM: Here is where logic would go to migrate/update an out-of-date schema...
            			}
            			
            		} catch (Exception e) {
            			
                		// ACLs
            			LOGGER.info("Creating non-hibernate tables for schema/bundle version: " + Activator.getBundleVersion());
                		jdbcTemplate.execute(sql.getAclSidCreateSql());
                		jdbcTemplate.execute(sql.getAclClassCreateSql());
                		jdbcTemplate.execute(sql.getAclObjectIdentityCreateSql());
                		jdbcTemplate.execute(sql.getAclEntryCreateSql());
                		
                		// External credentials (X.509 certs)
                		jdbcTemplate.execute(sql.getExternalCredentialCreateSql());
                		
                		// Configuration table (used to hold schema version)
                		jdbcTemplate.execute(sql.getConfigurationCreateSql());
                		
                		// Insert a row saying what the bundle/schema version was that was used when creating this DB.
                        jdbcTemplate.update(sql.getInsertConfigurationSql(), new PreparedStatementSetter() {
	                 		public void setValues(PreparedStatement ps) throws SQLException {
	                 			ps.setString(1, Activator.getBundleName());
	                 			ps.setString(2, Activator.getBundleVersion());
	                 		}});
                        
                        schemaVersion = Activator.getBundleVersion();            			
            		}
            		            		
    	    	} catch (BadSqlGrammarException ex){
    	    		// We want to ignore exceptions because the object already exists.
    	    		// This on was thrown by SQL Server
    	    		LOGGER.debug(ex.getMessage(), ex);
    	    	} catch (DataAccessResourceFailureException ex){
    	    		// This on was thrown by Derby
    	    		LOGGER.debug(ex.getMessage(), ex);
    	    	} catch (Exception e) {
    	    		// Log unexpected exceptions
    	    		LOGGER.debug(e.getMessage(), e);
    	    	}
                return null;
            }
        });
        
		return schemaVersion;
	}
		
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#getBundleVersion()
	 */
	public final String getBundleVersion() {
		return Activator.getBundleVersion();
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#getAuditEventDao()
	 */
	public final IAuditEventDao getAuditEventDao() {
		return (IAuditEventDao)applicationContext.getBean("auditEventDao");
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#getMigrationRecordDao()
	 */
	public final IMigrationRecordDao getMigrationRecordDao() {
		return (IMigrationRecordDao)applicationContext.getBean("migrationRecordDao");
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#getMultiTenancyRealmDao()
	 */
	public final IMultiTenancyRealmDao getMultiTenancyRealmDao() {
		return (IMultiTenancyRealmDao)applicationContext.getBean("multiTenancyRealmDao");
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#getSecurityPrincipalDao()
	 */
	public final ISecurityPrincipalDao getSecurityPrincipalDao() {
		return (ISecurityPrincipalDao)applicationContext.getBean("securityPrincipalDao");
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#getSecurityRoleDao()
	 */
	public final ISecurityRoleDao getSecurityRoleDao() {
		return (ISecurityRoleDao)applicationContext.getBean("securityRoleDao");
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#getJdbcTemplate()
	 */
	public final JdbcTemplate getJdbcTemplate() {
		return (JdbcTemplate)applicationContext.getBean("jdbcTemplate");
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#getSecurityDataSourceWrapper()
	 */
	public final ISecurityDataSourceWrapper getSecurityDataSourceWrapper() {
		return (ISecurityDataSourceWrapper)applicationContext.getBean("securityDataSourceWrapper");
	}
	
	/**
	 * 
	 * @return
	 */
	public final IAclSql getAclSql() {
		return (IAclSql)applicationContext.getBean("aclSql");
	}
	

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#getHibernateTransactionManager()
	 */
	public final ResourceTransactionManager getHibernateTransactionManager() {
		return (ResourceTransactionManager)applicationContext.getBean("hibernateTransactionManager");
	}
	
	/**
	 * 
	 * @param hibernateSessionFactory
	 */
	public final static void afterPropertiesSet(LocalSessionFactoryBean hibernateSessionFactory) {
		try {
            hibernateSessionFactory.afterPropertiesSet();
        } catch (Exception e) {
            throw new IllegalStateException("Could not initialize hibernate session factory bean, error: " + e.getMessage(), e);
        }	
	}
	
	/*
	 * 
	 * @param isRefreshing
	 */
	private static synchronized void setIsRefreshing(boolean isRefreshing) {
		PersistenceProvider.isRefreshing = isRefreshing;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#isRefreshing()
	 */
	public final synchronized boolean isRefreshing() {
		return PersistenceProvider.isRefreshing;
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#refresh()
	 */
	public final synchronized void refresh() {

	    PersistenceProvider.setIsRefreshing(true);
	    	    
	    PersistenceProvider.setIsRefreshing(false);
	}

	/*
	 * (non-Javadoc)
	 * @see com.compuware.frameworks.security.persistence.IPersistenceProvider#testJdbcConnection(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
   public void testJdbcConnection(
           String driverClassName,
           String connectionString,
           String serviceAccountUsername,
           String serviceAccountPassword) 
       throws 
           InvalidCredentialsException,
           InvalidConnectionException {
       
       Map<String, String> jdbcConfig = new HashMap<String, String>();
       jdbcConfig.put(ICompuwareSecurityJdbcConfiguration.JDBC_DRIVER_CLASS_NAME_KEY, driverClassName);
       jdbcConfig.put(ICompuwareSecurityJdbcConfiguration.JDBC_CONNECTION_STRING_KEY, connectionString);
       jdbcConfig.put(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_USERNAME_KEY, serviceAccountUsername);
       jdbcConfig.put(ICompuwareSecurityJdbcConfiguration.JDBC_SERVICE_ACCOUNT_PASSWORD_KEY, serviceAccountPassword);
       
       // See: http://community.jboss.org/wiki/HowToConfigureTheC3P0ConnectionPool
       ComboPooledDataSourceFactoryBean comboPool = null;
       
       ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
        try {
           Thread.currentThread().setContextClassLoader(ComboPooledDataSourceFactoryBean.class.getClassLoader());

           Properties properties = new Properties();
           properties.put("user", serviceAccountUsername);
           properties.put("password", serviceAccountPassword);
           
           comboPool = new ComboPooledDataSourceFactoryBean();
           comboPool.setDriverClass(driverClassName);
           comboPool.setJdbcUrl(connectionString);
           comboPool.setUsername(serviceAccountUsername);
           comboPool.setPassword(serviceAccountPassword);
           

           
           // APMOSECURITY-92: Minimize any delays on an invalid connection.
           DriverManager.setLoginTimeout(5);
           properties.setProperty("timeout", "5");
           comboPool.setAcquireRetryAttempts(1);
           comboPool.setAcquireIncrement(1);
           comboPool.setAcquireRetryDelay(500);         
           if (connectionString.contains(ICompuwareSecurityJdbcConfiguration.SQLSERVER_CONNECTION_STRING_PREFIX)) {
               // See: http://jtds.sourceforge.net/faq.html#driverImplementation
               properties.put("loginTimeout", "5"); // In seconds.
           } else if (connectionString.contains(ICompuwareSecurityJdbcConfiguration.ORACLE_CONNECTION_STRING_PREFIX)) {
               // See: http://docs.oracle.com/cd/E12840_01/wls/docs103/jdbc_drivers/oracle.html#wp1066413
               properties.put("ConnectionRetryCount", "0"); // The driver won't try to reconnect after an initial unsuccessful attempt.
               properties.put("ConnectionRetryDelay", "1"); // In seconds.
           } // We don't care about Derby, because we are using embedded and there is not possibility of invalid connection/network timeout.

               
               
           comboPool.setProperties(properties);
           comboPool.afterPropertiesSet();
           
           final DataSource dataSource = (DataSource)comboPool.getObject();
           boolean isReadOnly = dataSource.getConnection().getMetaData().isReadOnly();
           if (isReadOnly) {
               throw new InvalidConnectionException("Read only databases cannot be used [" + connectionString + "]");               
           }
               
        } catch (BadCredentialsException bce) {
            throw new InvalidCredentialsException("Could not authenticate using: [" + connectionString + "] and username: [" + serviceAccountUsername + "], error: " + bce.getLocalizedMessage(), bce);
        } catch (org.springframework.dao.DataAccessResourceFailureException darfe) {
            throw new InvalidCredentialsException("Could not authenticate using: [" + connectionString + "] and username: [" + serviceAccountUsername + "], error: " + darfe.getLocalizedMessage(), darfe);
        } catch (InvalidConnectionException ice) {
            throw ice;
        } catch (Exception e) {
            // Check for special case from Oracle where error message does not make sense to user, so we 
            // are stripping it off the final exception message sent back.
            if (e.getMessage().equals("Got minus one from a read call")) {
                throw new InvalidConnectionException("Could not connect using: [" + connectionString + "] and username: [" + serviceAccountUsername + "]", e);
            }
            
            throw new InvalidConnectionException("Could not connect using: [" + connectionString + "] and username: [" + serviceAccountUsername + "], error: " + e.getMessage(), e);            
       } finally {
           Thread.currentThread().setContextClassLoader(oldClassLoader);
           try {
               if (comboPool != null) {
                   comboPool.close();  
               }                   
           } catch (Exception e) {
               LOGGER.error("Could not close JDBC resources for testConnection(): " + e.getMessage(), e);
           }
        }
   }	
}