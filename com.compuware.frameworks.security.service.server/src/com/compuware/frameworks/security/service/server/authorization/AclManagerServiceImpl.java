/**
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
package com.compuware.frameworks.security.service.server.authorization;

import java.util.List;

import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import com.compuware.frameworks.security.service.api.authorization.IAclDomainObject;
import com.compuware.frameworks.security.service.api.authorization.IAclManagerService;
import com.compuware.frameworks.security.service.server.authorization.jdbc.CompuwareSecurityJdbcMutableAclService;

/**
 * 
 * @author tmyers
 *
 */
public final class AclManagerServiceImpl implements IAclManagerService {
	
    /* */
    private CompuwareSecurityJdbcMutableAclService compuwareSecurityJdbcMutableAclService;
        
    /* */
    private TransactionTemplate transactionTemplate;

    /**
     * 
     */
    public AclManagerServiceImpl() {
    	
    }
    
    /**
     * 
     * @param compuwareSecurityJdbcMutableAclService
     */
    public AclManagerServiceImpl(CompuwareSecurityJdbcMutableAclService compuwareSecurityJdbcMutableAclService) {
    	setCompuwareSecurityJdbcMutableAclService(compuwareSecurityJdbcMutableAclService);
    }

    /**
     * 
     * @param compuwareSecurityJdbcMutableAclService
     */
    public void setCompuwareSecurityJdbcMutableAclService(CompuwareSecurityJdbcMutableAclService compuwareSecurityJdbcMutableAclService) {
    	this.compuwareSecurityJdbcMutableAclService = compuwareSecurityJdbcMutableAclService;
    	
    	// TODO: TDM: Do away with explicit txn mgmt now that we have the txn/session interceptors.
    	this.transactionTemplate = new TransactionTemplate(new DataSourceTransactionManager(compuwareSecurityJdbcMutableAclService.getDataSource()));
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.authorization.acl.util.AclSecurityUtil#addPermission(com.compuware.frameworks.security.authorization.IAclDomainObject, org.springframework.security.acls.Permission, java.lang.Class)
     */
    public void addPermission(final IAclDomainObject secureObject, final Permission permission, final Class<?> clazz) {
    	addPermission(secureObject, new PrincipalSid(getUsername()), permission, clazz);
    }

    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.api.authorization.ICompuwareSecurityAclManager#addPermission(com.compuware.frameworks.security.service.api.authorization.IAclDomainObject, java.lang.String, org.springframework.security.acls.model.Permission, java.lang.Class)
     */
    public void addPermission(final IAclDomainObject secureObject, final String recipient, final Permission permission, final Class<?> clazz) {
    	addPermission(secureObject, new PrincipalSid(recipient), permission, clazz);
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.authorization.acl.util.AclSecurityUtil#addPermission(com.compuware.frameworks.security.authorization.IAclDomainObject, org.springframework.security.acls.sid.Sid, org.springframework.security.acls.Permission, java.lang.Class)
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
	public void addPermission(final IAclDomainObject securedObject, final Sid recipient, final Permission permission, final Class<?> clazz) {
    	
        transactionTemplate.execute(new TransactionCallback() {
            public Object doInTransaction(TransactionStatus arg0) {
            	            	
                MutableAcl acl = null;
                ObjectIdentity oid = new ObjectIdentityImpl(clazz.getCanonicalName(), securedObject.getId());

                try {
                    acl = (MutableAcl) compuwareSecurityJdbcMutableAclService.readAclById(oid);
                } catch (NotFoundException nfe) {
                    acl = compuwareSecurityJdbcMutableAclService.createAcl(oid);
                }       

                acl.insertAce(acl.getEntries().size(), permission, recipient, true);
                compuwareSecurityJdbcMutableAclService.updateAcl(acl);
            	            	
                return null;
            }
        });
    }
    
    /*
     * (non-Javadoc)
     * @see com.compuware.frameworks.security.authorization.acl.util.AclSecurityUtil#deletePermission(com.compuware.frameworks.security.authorization.IAclDomainObject, org.springframework.security.acls.sid.Sid, org.springframework.security.acls.Permission, java.lang.Class)
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
	public void deletePermission(final IAclDomainObject securedObject, final Sid recipient, final Permission permission, final Class<?> clazz) {
    	
        transactionTemplate.execute(new TransactionCallback() {
            public Object doInTransaction(TransactionStatus arg0) {
            	
                ObjectIdentity oid = new ObjectIdentityImpl(clazz.getCanonicalName(), securedObject.getId());
                MutableAcl acl = (MutableAcl) compuwareSecurityJdbcMutableAclService.readAclById(oid);

                // Remove all permissions associated with this particular recipient (string equality used to keep things simple)
                List<AccessControlEntry> entries = acl.getEntries();

                for (int i = 0; i < entries.size(); i++) {
                    if (entries.get(i).getSid().equals(recipient) && entries.get(i).getPermission().equals(permission)) {
                        acl.deleteAce(i);
                    }
                }

                compuwareSecurityJdbcMutableAclService.updateAcl(acl);
            	            	
                return null;
            }
        });
    }
    
    /*
     * 
     * @return
     */
    protected String getUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) auth.getPrincipal()).getUsername();
        } else {
            return auth.getPrincipal().toString();
        }
    }
}