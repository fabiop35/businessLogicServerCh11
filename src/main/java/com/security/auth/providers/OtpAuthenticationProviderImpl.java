package com.security.auth.providers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.security.auth.proxy.AuthenticationServerProxy;
import com.security.auth.OtpAuthentication;

@Component
public class OtpAuthenticationProviderImpl 
        implements AuthenticationProvider {

  @Autowired
  private AuthenticationServerProxy proxy;

  @Override
  public Authentication authenticate(
                    Authentication auth)
           throws AuthenticationException {
    
    String username = auth.getName();
    String code = 
      String.valueOf(auth.getCredentials());

   boolean result = 
              proxy.sendOTP(username,code);

   if (result){
    return new OtpAuthentication(username, 
                                      code);
   } else {
    throw new BadCredentialsException("Bad Credentials");
   }
   
  }

  @Override
  public boolean supports(Class<?> aClass){
    return OtpAuthentication.class.isAssignableFrom(aClass);
  }

}

