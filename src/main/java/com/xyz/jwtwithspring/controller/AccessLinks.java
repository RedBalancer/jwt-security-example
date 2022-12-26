package com.xyz.jwtwithspring.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Chunlong Zhang
 * @version 1.0.0
 * @ClassName AccessLinks.java
 * @Description @TODO
 * @createTime 2022年12月26日 10:22:00
 */

@RestController
public class AccessLinks {

    @GetMapping( "/hello" )
    public String sayHello() {
        return "hello";
    }

    @GetMapping( "/admin" )
    public String sayAdmin() {
        return "Admin";
    }

}
