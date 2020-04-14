package com.runaccepted.jwt.api.entity;

import lombok.Data;

@Data
public class Admin {

    private String id;

    private String username;

    private String password;

    public boolean equal(String name,String pwd){
        if (username.equals(name)&&password.equals(pwd)){
            return true;
        }
        return false;
    }
}
