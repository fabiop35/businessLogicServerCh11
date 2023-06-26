package com.security.repositories;

import com.security.entities.Privatekey;

import org.springframework.data.jpa.repository.JpaRepository;

public interface PrivatekeyRepository extends JpaRepository<Privatekey, String>{
  
    public Privatekey findPrivatekeyByUsername(String username);
}
