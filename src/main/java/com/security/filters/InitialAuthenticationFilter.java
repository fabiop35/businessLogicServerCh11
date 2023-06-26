package com.security.filters;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Base64;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.logging.Logger;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureAlgorithm;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.auth.UsernamePasswordAuthentication;
import com.security.auth.OtpAuthentication;
import com.security.repositories.PrivatekeyRepository;
import com.security.entities.Privatekey;


@Component
public class InitialAuthenticationFilter
              extends OncePerRequestFilter{

  @Autowired
  private AuthenticationManager
               authenticationManager;

  @Value("${jwt.signing.key}")
  private String signingKey;

  private final Logger logger = 
      Logger.getLogger(
    InitialAuthenticationFilter.class.getName() );
  
  @Autowired
  private PrivatekeyRepository keyRepository;

  @Override
  protected void doFilterInternal(
         HttpServletRequest request,
         HttpServletResponse response,
                     FilterChain filter)
                 throws ServletException, 
                              IOException{
   logger.info("》》》doFilterInternal"); 
    String username = 
        request.getHeader("username");
    String password = 
        request.getHeader("password");
    String code =
        request.getHeader("code");

    if(code == null){
     Authentication a =
      new UsernamePasswordAuthentication(
                       username, password);
     authenticationManager.authenticate(a);
    }else{
     Authentication a =
      new OtpAuthentication(username,code);
     authenticationManager.authenticate(a);

     //SecretKey key = Keys.hmacShaKeyFor(
     //        signingKey.getBytes(
     //            StandardCharsets.UTF_8));

     //ALG HS256
     SecretKey key = 
         Keys.secretKeyFor(
                  SignatureAlgorithm.HS256);

    byte[] rawData = key.getEncoded();
    logger.info("rawData: "+ rawData);
    logger.info("KEY  Base64:  "+
         Base64.getEncoder()
                  .encodeToString(rawData));

     //Store the generated Key
     Privatekey userKey = new Privatekey();
     userKey.setUsername(username);
     userKey.setPrivatekey(
               Base64.getEncoder()
                .encodeToString(rawData) );
     keyRepository.save(userKey);
     
     String jwt = Jwts.builder()
    .setClaims(Map.of("username",username)) 
    .signWith(key).compact();
     response.setHeader("Authorization",
                                      jwt);
    }
  }

  @Override
  protected boolean shouldNotFilter(
          HttpServletRequest request){

    return !request.getServletPath()
                     .equals("/login");
  }


}
