package com.security.web.controllers;

import org.springframework.web.bind.annotation.RestController;

import org.springframework.web.bind.annotation.GetMapping;

@RestController
public class TestJWTController {

  @GetMapping("/testJWT")
  public String testJWT(){

    return "testJWT OK!";
  }

}
