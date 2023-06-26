package com.security.entities;


import javax.persistence.Id;
import javax.persistence.Entity;

import lombok.Data;

@Data
@Entity
public class Privatekey {
    
    @Id
    private String username;
    private String privatekey;
}
