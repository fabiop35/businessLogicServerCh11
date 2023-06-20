package com.security.auth;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class OtpAuthentication extends 
     UsernamePasswordAuthenticationToken {

    public OtpAuthentication(
                   Object principal,
                   Object credentials){

        super(principal, credentials);
    }
}

