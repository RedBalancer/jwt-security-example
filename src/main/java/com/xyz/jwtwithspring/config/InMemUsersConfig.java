package com.xyz.jwtwithspring.config;

import com.xyz.jwtwithspring.filter.JwtAuthenticationFilter;
import com.xyz.jwtwithspring.filter.JwtAuthorizationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author Chunlong Zhang
 * @version 1.0.0
 * @ClassName InMemUsersConfig.java
 * @Description @TODO
 * @createTime 2022年12月19日 19:33:00
 */

@Configuration
public class InMemUsersConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure( AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser( "zcl" ).password( "123" ).roles( "USER" )
                .and().withUser( "admin" ).password( "123" ).roles( "ADMIN" );
    }

    @Override
    public void configure(HttpSecurity http ) throws Exception {
        http.authorizeRequests().antMatchers( "/hello" ).hasRole( "USER" )
                .antMatchers( "/admin" ).hasRole( "ADMIN" )
                .antMatchers( HttpMethod.POST, "/login" ).permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore( new JwtAuthenticationFilter( "/login", authenticationManager() ), UsernamePasswordAuthenticationFilter.class )
                .addFilterBefore( new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class )
                .csrf().disable();
    }

    /**
     * 使用原始密码，不加密
     * @return
     */
    @Bean
    PasswordEncoder getPasswordEncoder() {
        PasswordEncoder instance = NoOpPasswordEncoder.getInstance();
        return instance;
    }
}
