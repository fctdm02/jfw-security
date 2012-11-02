/**
 * These materials contain confidential information and trade secrets of Compuware Corporation.
 * You shall maintain the materials as confidential and shall not disclose its contents to any
 * third party except as may be required by law or regulation.  Use, disclosure, or reproduction
 * is prohibited without the prior express written permission of Compuware Corporation.
 * 
 * All Compuware products listed within the materials are trademarks of Compuware Corporation.
 * All other company or product emails are trademarks of their respective owners.
 * 
 * Copyright 2010 by Compuware Corporation.  All rights reserved.
 * 
 */
package com.compuware.frameworks.security.service.api.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.compuware.frameworks.security.service.api.model.ws.JaxbGrantedAuthorityAdapter;


/**
 * This class encapsulates the two states of an authentication request/response use case:
 * <ol>
 * <li><b>Unauthenticated:</b> <code>username/credentials</code> are set and are given to 
 * the authentication provider for validation/rejection of the request based upon the validity 
 * of the credentials (here, a username and password combination) An instance in this state is 
 * assumed to be created by the service provider/calling application.
 * <p>&nbsp;<p>
 * <li><b>Authenticated:</b> <code>user/authorities/authenticationDetails</code> are set and is 
 * assumed to be created by the authentication provider upon successful authentication.  The 
 * <code>username/credentials</code> are not set, as the <code>user</code> object has all the needed 
 * state of the real-world user.
 * </ol>    
 * 
 * @author tmyers
 * 
 */
@XmlRootElement
public final class CompuwareSecurityAuthenticationToken implements Authentication, UserDetails, Serializable {

   /** */
   private static final long serialVersionUID = 1L;
   
   // Unauthenticated state.
   /**
    * The identity of the principal wishing to be authenticated. 
    */
   @XmlElement
   private String username;
   
   /**
    * The credentials that prove the principal is correct.  In this implementation, 
    * we use a password that is provided by a user wishing to prove their identity.
    * This maps to the 'credentials' field of Authentication and is erased after the 
    * principal (i.e. user) is authenticated.
    */
   private Object credentials;
   
   /**
    * The IP Address of the workstation that the user initiated the authentication from.
    */
   @XmlElement
   private String originatingIpAddress;

   /**
    * The hostname of the workstation that the user initiated the authentication from (if one exists).
    */
   @XmlElement
   private String originatingHostname;
   
   /**
    * The identity of the multi-tenancy realm that the user wishes to authenticate in. 
    */
   @XmlElement
   private String realmName;
      
   
   // Authenticated state.
   /**
    * This field is maintained for compatibility with V0 version of the Web Service.
    * 
    * 
    * Used for session management. The time at which the user last had any activity. 
    * (this field is mutable and is to be set to the current time each time
    * the principal had any activity) This time is used to check against the current 
    * system time for determining whether or not the session has timed out because of
    * user inactivity.
    * @deprecated
    */
   @XmlElement
   private java.util.Date lastActiveTime;

/**
    * The user that was authenticated given the credentials.
    */
   @XmlElement
   private AbstractUser userObject;
   
   /**
    * Used for session management. The time at which the user was authenticated 
    * (assumes that clocks are either synchronized or within a tolerable variance).
    * This time is used to check against the current system time for determining 
    * whether or not the max session length has been exceeded.
    */
   @XmlElement
   private java.util.Date authenticationTime;
   
   /**
    * This collection is determined basically by the existence of the
    * principal to role mappings assigned to this user explicitly, any
    * securityGroups that the user explicitly belongs to (or implicitly, through
    * the group hierarchy).  Similarly, any roles that are parent roles
    * of these role mappings are also included in this list of authorities. 
    */   
   private Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
   
      
   // Authentication State flag.
   /**
     * Used to indicate to {@code AbstractSecurityInterceptor} whether it should present the
     * authentication token to the <code>AuthenticationManager</code>. Typically an <code>AuthenticationManager</code>
     * (or, more often, one of its <code>AuthenticationProvider</code>s) will return an immutable authentication token
     * after successful authentication, in which case that token can safely return <code>true</code> to this method.
     * Returning <code>true</code> will improve performance, as calling the <code>AuthenticationManager</code> for
     * every request will no longer be necessary.
     */
    private boolean authenticated = false;
   
    /* 
     * JAXB is the only intended caller of the private no-arg constructor. 
     * This flag is used to allow JAXB to invoke the setAuthenticated method
     * when reconstructing a security token returned from a web service call.
     */  
    private boolean jaxbCaller = false;


    /**
     * This constructor is for web service support.
     */
    @SuppressWarnings("unused")
	private CompuwareSecurityAuthenticationToken() {
        jaxbCaller = true;
        this.authenticated = false;
    }

    /**
     * This constructor can be safely used by any code that wishes to create an Authentication token,
     * as the {@link #isAuthenticated()} will return false. That is, this represents an authentication request.
     * 
     * @param username
     * @param clearTextPassword
     * @param originatingIpAddress
     * @param originatingHostname
     * @param realmName
     */
    public CompuwareSecurityAuthenticationToken(
        String username, 
        ClearTextPassword clearTextPassword,
        String originatingIpAddress,
        String originatingHostname,
        String realmName) {
        this(
            username,
            clearTextPassword.getClearTextPassword(),
            originatingIpAddress,
            originatingHostname,
            realmName);
    }
    
    /**
     * This constructor can be safely used by any code that wishes to create an Authentication token,
     * as the {@link #isAuthenticated()} will return false. That is, this represents an authentication request.
     * 
     * @param username
     * @param credentials
     * @param originatingIpAddress
     * @param originatingHostname
     * @param realmName
     */
    public CompuwareSecurityAuthenticationToken(
    	String username, 
    	String credentials,
        String originatingIpAddress,
        String originatingHostname,
        String realmName) {
        this.username = username;
        this.credentials = credentials;
        this.originatingIpAddress = originatingIpAddress;
        this.originatingHostname = originatingHostname;         
        this.realmName = realmName;
        this.authenticated = false;
    }

    /**
     * This constructor should only be used by <code>AuthenticationManager</code> or <code>AuthenticationProvider</code>
     * implementations that are satisfied with producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
     * authentication token.
     *
     * @param user The identity of the principal that has just been authenticated
     * @param authorities The granted authorities assigned to the principal
     * @param authenticationTime The time at which the user was authenticated (assumes that clocks are either synchronized or within a tolerable variance).
     * @param originatingIpAddress The IP Address of the workstation that the user initiated the authentication from.
     * @param originatingHostname The hostname of the workstation that the user initiated the authentication from (if one exists).
     * 
     * NOTE: It is assumed that authenticationTime, originatingIpAddress and originatingHostname are taken from the "unauthenticated" 
     * form of the authentication token (that is, the one that the client created when performing the authentication request).  We need
     * this information so that we can properly construct Audit Events.
     */
    public CompuwareSecurityAuthenticationToken(
        AbstractUser userObject, 
        Collection<GrantedAuthority> authorities,
        java.util.Date authenticationTime,
        String originatingIpAddress,
        String originatingHostname) {
    	
        
        if (userObject == null) {
            throw new IllegalArgumentException("userObject cannot be null.");
        }
        this.userObject = userObject;
        if (authorities != null && authorities.size() > 0) {
            this.authorities = authorities;    
        }
        this.authenticationTime = authenticationTime;
        this.originatingIpAddress = originatingIpAddress;
        this.originatingHostname = originatingHostname; 
        this.lastActiveTime = authenticationTime;
        this.authenticated = true;
    }
    
  // ********************************************************
  // Methods to implement the Authentication interface.
  // ********************************************************
  
  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.Authentication#getCredentials()
   */
  public Object getCredentials() {
      
      if (authenticated) {
          throw new IllegalStateException("getCredentials() should not be called after successful authentication.");
      }
      return this.credentials;
  }

  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.Authentication#getDetails()
   */
  public Object getDetails() {
      
      Map<String, Object> detailsMap = new HashMap<String, Object>();
      detailsMap.put("authenticationTime", this.authenticationTime);
      detailsMap.put("originatingIpAddress", this.originatingIpAddress);
      detailsMap.put("originatingHostname", this.originatingHostname);   
      return detailsMap;
  }
  
  /**
   * 
   * @return authenticated user object
   */
  public AbstractUser getUserObject() {
      return this.userObject;
  }
  
  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.Authentication#getPrincipal()
   */
  public Object getPrincipal() {
      return getUserObject();
  }
  
  /**
   * @param authorities the authorities to set
   */
  void setAuthorities(Collection<GrantedAuthority> authorities) {
      this.authorities.addAll(authorities);
  }

  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.Authentication#getAuthorities()
   */
  @XmlElementWrapper(name="authorities")
  @XmlJavaTypeAdapter(JaxbGrantedAuthorityAdapter.class)
  @XmlElement(name="compuwareGrantedAuthority")       
  public Collection<GrantedAuthority> getAuthorities() {
      return authorities;
  }
  
  /**
   * 
   * @param roleName The role name with which to do an authorization
   * check against. e.g. <code>ROLE_APM_REPORTING_POWERUSER</code>
   * @return <code>true</code> if the user is authorized for a given role.
   */
  public final boolean isUserAuthorized(String roleName) {
      
      Iterator<GrantedAuthority> iterator = this.authorities.iterator();
      while (iterator.hasNext()) {

          GrantedAuthority grantedAuthority = iterator.next();
          if (grantedAuthority.getAuthority().equals(roleName)) {
              return true;
          }
      }
      return false;
  }
  
  /*
   * (non-Javadoc)
   * @see java.security.Principal#getName()
   */
  public String getName() {
      
    if (!authenticated) {
       return this.username;
    }
    if (this.userObject == null) {
       throw new IllegalStateException("User must be set in order to call getName().");
    }      
    return this.userObject.getUsername();
  } 
  
  /**
   * 
   * @return realmName
   */
  public String getRealmName() {
      
      String realm = null; 
      if (this.realmName != null) {
          realm = this.realmName;
      } else if (this.userObject != null) {
          realm = this.userObject.getMultiTenancyRealm().getRealmName();
      } else {
          throw new IllegalStateException("Both realmName and userObject cannot be null.");
      }
      return realm;
  }

  /**
   * @return the originatingIpAddress
   */
  public String getOriginatingIpAddress() {
      return this.originatingIpAddress;
  }

  /**
   * @return the originatingHostname
   */
  public String getOriginatingHostname() {
      return this.originatingHostname;
  }
  
  /**
   * 
   * @return authenticationTime
   */
  public java.util.Date getAuthenticationTime() {
      
      return this.authenticationTime;
  }

    /**
     * 
     */
    public void updateLastActiveTime() {
    	this.lastActiveTime = new java.util.Date(System.currentTimeMillis());
    }

    /**
     * 
     * @return lastActiveTime
     */
    public java.util.Date getLastActiveTime() {
    	return this.lastActiveTime;
    }
    
  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.Authentication#isAuthenticated()
   */
  public boolean isAuthenticated() {
      
    return this.authenticated;
  }

  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.Authentication#setAuthenticated(boolean)
   */
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
      
      if (isAuthenticated && !jaxbCaller) {
       throw new IllegalArgumentException("Cannot set isAuthenticated to true (Only the authentication provider can do this via use of the constructor that takes a collection of granted authorities)");
      }
      this.authenticated = isAuthenticated;
  }


  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.userdetails.UserDetails#getPassword()
   */
  public String getPassword() {
      
      if (authenticated) {
          throw new IllegalStateException("getPassword() should not be called after successful authentication.");
      }
      return this.credentials.toString();
  }
  
  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.userdetails.UserDetails#getUsername()
   */
  public String getUsername() {
      
      if (authenticated) {
          return this.userObject.getUsername();
      }
      return this.username;
  }
  
  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.userdetails.UserDetails#isAccountNonExpired()
   */
  public boolean isAccountNonExpired() {
      
      if (!authenticated) {
          throw new IllegalStateException("isAccountNonExpired() should not be called before successful authentication.");
      }
      if (this.userObject instanceof SecurityUser) {
          SecurityUser securityUser = (SecurityUser)this.userObject;
          return securityUser.isAccountNonExpired();
      }
      return true;
  }
  
  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.userdetails.UserDetails#isAccountNonLocked()
   */
  public boolean isAccountNonLocked() {
      
      if (!authenticated) {
          throw new IllegalStateException("isAccountNonLocked() should not be called before successful authentication.");
      }
      if (this.userObject instanceof SecurityUser) {
          SecurityUser securityUser = (SecurityUser)this.userObject;
          return securityUser.isAccountNonLocked();
      }
      return true;
  }
  
  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.userdetails.UserDetails#isCredentialsNonExpired()
   */
  public boolean isCredentialsNonExpired() {
      
      if (!authenticated) {
          throw new IllegalStateException("isCredentialsNonExpired() should not be called before successful authentication.");
      }
      if (this.userObject instanceof SecurityUser) {
          SecurityUser securityUser = (SecurityUser)this.userObject;
          return securityUser.isCredentialsNonExpired();
      }
      return true;
  }

  /*
   * (non-Javadoc)
   * @see org.springframework.security.core.userdetails.UserDetails#isEnabled()
   */
  public boolean isEnabled() {
      
      if (!authenticated) {
          throw new IllegalStateException("isEnabled() should not be called before successful authentication.");
      }
      if (this.userObject instanceof SecurityUser) {
          SecurityUser securityUser = (SecurityUser)this.userObject;
          return securityUser.isEnabled();
      }
      return true;
      
  }
  
  /*
   * (non-Javadoc)
   * @see java.lang.Object#equals(java.lang.Object)
   */
  @Override
  public boolean equals(Object object) {
      
      if (!(object instanceof CompuwareSecurityAuthenticationToken)) {
          return false;
      }
      
      CompuwareSecurityAuthenticationToken that = (CompuwareSecurityAuthenticationToken)object;
      
      String thisStringRepresentation = this.toString();
      String thatStringRepresentation = that.toString();
      
      return thisStringRepresentation.equals(thatStringRepresentation);
  }

  /*
   * (non-Javadoc)
   * @see java.lang.Object#hashCode()
   */
  @Override
  public int hashCode() {
      
      return this.toString().hashCode();
  }

 /*
  * (non-Javadoc)
  * @see java.lang.Object#toString()
  */
  @Override
 public String toString() {
      
    StringBuilder sb = new StringBuilder();
    sb.append("{");
    sb.append(this.getClass().getSimpleName());
    sb.append(": ");
    
    if (this.authenticated) {
       sb.append("user: ");
       if (this.userObject != null) {
           sb.append(this.userObject.getUsername());
       }         
       sb.append(", authorities: ");
       sb.append(this.authorities);
       sb.append(", authenticationTime: ");
       sb.append(this.authenticationTime);
    } else {
       sb.append("username: ");
       sb.append(this.username);
       sb.append(", credentials: [PROTECTED], realmName: ");
       sb.append(this.realmName);         
    }
    
    sb.append(", originatingIpAddress: ");
    sb.append(this.originatingIpAddress);
    sb.append(", originatingHostname: ");
    sb.append(this.originatingHostname);      
    sb.append(", isAuthenticated: ");
    sb.append(this.authenticated);      
    sb.append("}");
    return sb.toString();
  }
}