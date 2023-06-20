package com.security.auth.providers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.security.auth.proxy.AuthenticationServerProxy;
import com.security.auth.UsernamePasswordAuthentication;

@Component
public class UsernamePasswordAuthenticationProviderImpl 
    implements AuthenticationProvider{
  
  @Autowired
  private AuthenticationServerProxy proxy;

  @Override  
  public Authentication authenticate(
                  Authentication auth){

   String username = auth.getName();
   String password = 
    String.valueOf(auth.getCredentials());
    
   proxy.sendAuth(username, password);

   return new UsernamePasswordAuthenticationToken(username, password);
 }
 @Override
 public boolean supports(Class<?> aClass){
    return UsernamePasswordAuthentication.class.isAssignableFrom(aClass);
 }
}
