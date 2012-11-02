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
package com.compuware.frameworks.security.service.server.authorization.acl;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AbstractAclVoter;
import org.springframework.security.acls.domain.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.domain.SidRetrievalStrategyImpl;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.model.SidRetrievalStrategy;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.compuware.frameworks.security.service.api.exception.ServiceException;
import com.compuware.frameworks.security.service.api.management.IManagementService;
import com.compuware.frameworks.security.service.api.model.CompuwareSecurityAuthenticationToken;

/**
 * This class has the ability to apply ACLs against groups that the authenticated user belongs to.
 * 
 * 
 *
 * <p>
 * Given a domain object instance passed as a method argument, ensures the principal has appropriate permission
 * as indicated by the {@link AclService}.
 * <p>
 * The <tt>AclService</tt> is used to retrieve the access control list (ACL) permissions associated with a
 * domain object instance for the current <tt>Authentication</tt> object.
 * <p>
 * The voter will vote if any  {@link ConfigAttribute#getAttribute()} matches the {@link #processConfigAttribute}.
 * The provider will then locate the first method argument of type {@link #processDomainObjectClass}. Assuming that
 * method argument is non-null, the provider will then lookup the ACLs from the <code>AclManager</code> and ensure the
 * principal is {@link Acl#isGranted(List,
 * List, boolean)} when presenting the {@link #requirePermission} array to that
 * method.
 * <p>
 * If the method argument is <tt>null</tt>, the voter will abstain from voting. If the method argument
 * could not be found, an {@link AuthorizationServiceException} will be thrown.
 * <p>
 * In practical terms users will typically setup a number of <tt>AclEntryVoter</tt>s. Each will have a
 * different {@link #setProcessDomainObjectClass processDomainObjectClass}, {@link #processConfigAttribute} and
 * {@link #requirePermission} combination. For example, a small application might employ the following instances of
 * <tt>AclEntryVoter</tt>:
 *  <ul>
 *      <li>Process domain object class <code>BankAccount</code>, configuration attribute
 *      <code>VOTE_ACL_BANK_ACCONT_READ</code>, require permission <code>BasePermission.READ</code></li>
 *      <li>Process domain object class <code>BankAccount</code>, configuration attribute
 *      <code>VOTE_ACL_BANK_ACCOUNT_WRITE</code>, require permission list <code>BasePermission.WRITE</code> and
 *      <code>BasePermission.CREATE</code> (allowing the principal to have <b>either</b> of these two permissions)</li>
 *      <li>Process domain object class <code>Customer</code>, configuration attribute
 *      <code>VOTE_ACL_CUSTOMER_READ</code>, require permission <code>BasePermission.READ</code></li>
 *      <li>Process domain object class <code>Customer</code>, configuration attribute
 *      <code>VOTE_ACL_CUSTOMER_WRITE</code>, require permission list <code>BasePermission.WRITE</code> and
 *      <code>BasePermission.CREATE</code></li>
 *  </ul>
 *  Alternatively, you could have used a common superclass or interface for the {@link #processDomainObjectClass}
 * if both <code>BankAccount</code> and <code>Customer</code> had common parents.</p>
 *  <p>If the principal does not have sufficient permissions, the voter will vote to deny access.</p>
 *  <p>All comparisons and prefixes are case sensitive.</p>
 *
 * @author Ben Alex
 * @author tmyers
 */
public final class CompuwareSecurityAclEntryVoter extends AbstractAclVoter {
	
	/* */
	private final Logger logger = Logger.getLogger(CompuwareSecurityAclEntryVoter.class);
			
    private AclService aclService;
    private ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy = new ObjectIdentityRetrievalStrategyImpl();
    private SidRetrievalStrategy sidRetrievalStrategy = new SidRetrievalStrategyImpl();
    private String internalMethod;
    private String processConfigAttribute;
    private List<Permission> requirePermission;
    private IManagementService managementService;

    //~ Constructors ===================================================================================================
	/**
	 * 
	 * @param aclService
	 * @param processConfigAttribute
	 * @param requirePermission
	 * @param managementService
	 */
    public CompuwareSecurityAclEntryVoter(
    		AclService aclService, 
    		String processConfigAttribute, 
    		Permission[] requirePermission,
    		IManagementService managementService) {
    	
    	this.managementService = managementService;
    	
        Assert.notNull(processConfigAttribute, "A processConfigAttribute is mandatory");
        Assert.notNull(aclService, "An AclService is mandatory");

        if ((requirePermission == null) || (requirePermission.length == 0)) {
            throw new IllegalArgumentException("One or more requirePermission entries is mandatory");
        }

        this.aclService = aclService;
        this.processConfigAttribute = processConfigAttribute;
        this.requirePermission = Arrays.asList(requirePermission);
    }

    //~ Methods ========================================================================================================
    /**
     * Optionally specifies a method of the domain object that will be used to obtain a contained domain
     * object. That contained domain object will be used for the ACL evaluation. This is useful if a domain object
     * contains a parent that an ACL evaluation should be targeted for, instead of the child domain object (which
     * perhaps is being created and as such does not yet have any ACL permissions)
     *
     * @return <code>null</code> to use the domain object, or the name of a method (that requires no arguments) that
     *         should be invoked to obtain an <code>Object</code> which will be the domain object used for ACL
     *         evaluation
     */
    protected String getInternalMethod() {
        return internalMethod;
    }

    /**
     * 
     * @param internalMethod
     */
    public void setInternalMethod(String internalMethod) {
        this.internalMethod = internalMethod;
    }

    /**
     * 
     * @return
     */
    protected String getProcessConfigAttribute() {
        return processConfigAttribute;
    }

    /**
     * 
     * @param objectIdentityRetrievalStrategy
     */
    public void setObjectIdentityRetrievalStrategy(ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy) {
        Assert.notNull(objectIdentityRetrievalStrategy, "ObjectIdentityRetrievalStrategy required");
        this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
    }

    /**
     * 
     * @param sidRetrievalStrategy
     */
    public void setSidRetrievalStrategy(SidRetrievalStrategy sidRetrievalStrategy) {
        Assert.notNull(sidRetrievalStrategy, "SidRetrievalStrategy required");
        this.sidRetrievalStrategy = sidRetrievalStrategy;
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.access.AccessDecisionVoter#supports(org.springframework.security.access.ConfigAttribute)
     */
    public boolean supports(ConfigAttribute attribute) {
        if ((attribute.getAttribute() != null) && attribute.getAttribute().equals(getProcessConfigAttribute())) {
            return true;
        }
        return false;
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.access.AccessDecisionVoter#vote(org.springframework.security.core.Authentication, java.lang.Object, java.util.Collection)
     */
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {

        for (ConfigAttribute attribute: attributes) {
            if (!this.supports(attribute)) {            	
                continue;
            }
            
            return vote(authentication, object);
        }

        // No configuration attribute matched, so abstain
        return ACCESS_ABSTAIN;
    }
    
    /*
     * 
     * @param authentication
     * @param object
     * @return
     */
    private int vote(Authentication authentication, Object object) {
    	
    	int result = ACCESS_DENIED;
    	
        // Need to make an access decision on this invocation
        // Attempt to locate the domain object instance to process
        Object domainObject = getDomainObjectInstance(object);

        // If domain object is null, vote to abstain
        if (domainObject == null) {
        	
            logger.debug("Voting to abstain - domainObject is null");
            result = ACCESS_ABSTAIN;
            
        } else {
        	
            // Evaluate if we are required to use an inner domain object
            domainObject = hasInnerDomainObject(domainObject);

            // Obtain the OID applicable to the domain object
            ObjectIdentity objectIdentity = objectIdentityRetrievalStrategy.getObjectIdentity(domainObject);

            // Obtain the SIDs applicable to the principal
            List<Sid> sids = sidRetrievalStrategy.getSids(authentication);

            // Obtain the SIDs applicable to the groups that this authentication belongs to.
            if (!(authentication instanceof CompuwareSecurityAuthenticationToken)) {
            	throw new ServiceException("authentication must be an instance of CompuwareSecurityAuthenticationToken, yet is: " + authentication.getClass().getCanonicalName());
            }
            CompuwareSecurityAuthenticationToken compuwareSecurityAuthenticationToken = (CompuwareSecurityAuthenticationToken)authentication;
            CompuwareSecurityAclUtils.addSidsForUserGroups(sids, compuwareSecurityAuthenticationToken, managementService);
            
            try {
            	
                // Lookup only ACLs for SIDs we're interested in
                Acl acl = aclService.readAclById(objectIdentity, sids);
                if (acl.isGranted(requirePermission, sids, false)) {
                    logger.debug("Voting to grant access");
                    result = ACCESS_GRANTED;
                } else {
                    logger.debug("Voting to deny access - ACLs returned, but insufficient permissions for this principal");
                    result = ACCESS_DENIED;
                }
                
            } catch (NotFoundException nfe) {
                logger.debug("Voting to deny access - no ACLs returned");
                result =  ACCESS_DENIED;
            }
        }
        
        return result;
    }
    
    /*
     * 
     * @param domainObject
     * @return
     */
    private Object hasInnerDomainObject(Object domainObject) {

        if (StringUtils.hasText(internalMethod)) {
            try {
                Class<?> clazz = domainObject.getClass();
                Method method = clazz.getMethod(internalMethod, new Class[0]);
                return method.invoke(domainObject, new Object[0]);
            } catch (NoSuchMethodException nsme) {
                throw new AuthorizationServiceException("Object of class '" + domainObject.getClass() + "' does not provide the requested internalMethod: " + internalMethod, nsme);
            } catch (IllegalAccessException iae) {
                throw new AuthorizationServiceException("Problem invoking internalMethod: " + internalMethod + " for object: " + domainObject, iae);
            } catch (InvocationTargetException ite) {
                throw new AuthorizationServiceException("Problem invoking internalMethod: " + internalMethod + " for object: " + domainObject, ite);
            }
        }
        
        return domainObject;
    }
}
