package com.runaccepted.jwt.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class JwtClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtClientApplication.class, args);
    }

}
