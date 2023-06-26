package com.security.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
//import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
//import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Logger;
import java.util.Base64;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.security.Keys;
//import io.jsonwebtoken.SignatureAlgorithm;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.auth.UsernamePasswordAuthentication;
import com.security.entities.Privatekey;
import com.security.repositories.PrivatekeyRepository;
import java.util.Optional;
import java.util.logging.Level;
import org.springframework.beans.factory.annotation.Autowired;

@Component
public class JwtAuthenticationFilter 
         extends OncePerRequestFilter {

 //@Value("${jwt.signing.key}")
 //private String signingKey;
 
 @Autowired
 private PrivatekeyRepository keyRepository;

 private static final Logger logger = 
     Logger.getLogger(
             JwtAuthenticationFilter.class.getName() );

 @Override
 protected void doFilterInternal(
         HttpServletRequest request,
         HttpServletResponse response,
         FilterChain filter)
    throws ServletException, IOException {

    String jwt = "";

    jwt = request.getHeader("Authorization");
    /* Get the key using hmac
    SecretKey key = Keys
            .hmacShaKeyFor(signingKey
        .getBytes(StandardCharsets.UTF_8));
   */
    
    //Getting the Key generated previously (HS256)
    logger.info("<---------------‐------------------------->");
    logger.info("<------- INI GETTING USER's PRIVATE KEY -->");
    logger.info("<---------------‐------------------------->");
    Base64.Decoder decoder = Base64.getUrlDecoder();

    String[] chunks = jwt.split("\\.");
    String header = new String(decoder.decode(chunks[0]));
    String payload = new String(decoder.decode(chunks[1]));
    String signature = new String(decoder.decode(chunks[2]));
    logger.log(Level.INFO, "-> JWT.Payload: {0}", payload);
    logger.log(Level.INFO, "-> JWT.Header: {0}", header);
    logger.log(Level.INFO, "-> JWT.Signature: {0}", signature);

   logger.info("^^ORIGINAL JWT: :"+jwt);
   //jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFuaWJhbCJ9.vzLLZna67WIAEfcW69hmvla7P3N1wLb3KYHWNT7SXA0";

   //logger.info("||||| Tamper Jwt: "+jwt);
 
   //Extract the username from the payload
   ObjectMapper mapper = new ObjectMapper();
   JsonNode rootNode = 
                  mapper.readTree(payload);
    JsonNode usernameNode = rootNode.path("username");
    logger.log(Level.INFO, "> UsernameJSON = {0}", usernameNode.asText());
    
    Privatekey userKey =  keyRepository
                .findPrivatekeyByUsername(
                     usernameNode.asText());
    logger.log(Level.INFO, ">>>  USER''s PRIVATE KEY: {0}", userKey.getPrivatekey());
    
    /*SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    byte[] rawData = key.getEncoded();
    logger.info("××× JWT: Key base64:  "+Base64.getEncoder().encodeToString(rawData));*/
    
    Claims claims = Jwts.parserBuilder()
     .setSigningKey(userKey.getPrivatekey())
        .build()
        .parseClaimsJws(jwt)
        .getBody();

    String username =
        String.valueOf(
                claims.get("username") );
    logger.log(Level.INFO, "\u300b\u300b\u300bClaims.username: {0}", username);

    GrantedAuthority a = 
        new SimpleGrantedAuthority("user");
     var auth = 
         new UsernamePasswordAuthentication(
               username, null, List.of(a));
    
    SecurityContextHolder.getContext().
                 setAuthentication(auth);

   filter.doFilter(request, response);
 }

 @Override
 protected boolean shouldNotFilter(
         HttpServletRequest request){

     return request.getServletPath()
                        .equals("/login");

 }
}
