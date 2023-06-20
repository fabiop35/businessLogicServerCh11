package com.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.security.filters.InitialAuthenticationFilter;
import com.security.filters.JwtAuthenticationFilter;
import com.security.auth.providers.UsernamePasswordAuthenticationProviderImpl;
import com.security.auth.providers.OtpAuthenticationProviderImpl;

@Configuration
public class SecurityConfig
    extends WebSecurityConfigurerAdapter {

 @Autowired
 private InitialAuthenticationFilter
              initialAuthenticationFilter;

 @Autowired
 private JwtAuthenticationFilter
               jwtAuthenticationFilter;

 @Autowired
 private 
 UsernamePasswordAuthenticationProviderImpl
        userPasswordAuthenticationProvider;

 @Autowired
 private OtpAuthenticationProviderImpl 
                 otpAuthenticationProvider;

 @Override
 protected void configure(
    AuthenticationManagerBuilder auth){
    
    auth.authenticationProvider(
          otpAuthenticationProvider)
        .authenticationProvider(
    userPasswordAuthenticationProvider);
 }

 @Override
 protected void configure(
                     HttpSecurity http) 
                        throws Exception{
    
    http.csrf().disable();
    http.addFilterAt(
        initialAuthenticationFilter,
          BasicAuthenticationFilter.class)
        .addFilterAfter(
          jwtAuthenticationFilter, 
           BasicAuthenticationFilter.class);
 }

 @Override
 @Bean
 protected AuthenticationManager 
             authenticationManager()
                         throws Exception {

    return super.authenticationManager();
 }

}
