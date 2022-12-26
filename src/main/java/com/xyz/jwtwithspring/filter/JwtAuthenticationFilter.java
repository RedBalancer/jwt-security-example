package com.xyz.jwtwithspring.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * @author Chunlong Zhang
 * @version 1.0.0
 * @ClassName JwtAuthenticationFilter.java
 * @Description 认证用Filter（验证用户名口令）
 * @createTime 2022年12月19日 19:17:00
 */

@Slf4j
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public JwtAuthenticationFilter(String defaultFilterProcessesUrl, AuthenticationManager authenManager) {
        super(new AntPathRequestMatcher( defaultFilterProcessesUrl ) );
        setAuthenticationManager( authenManager );
    }

    /**
     * 验证成功后，将用户名角色写成JWT token，返回给前台。
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
//        super.successfulAuthentication(request, response, chain, authResult);
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        String name = authResult.getName();
        String roles = authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
        log.info( "Name: " + name + ", principle: " + authResult.getPrincipal() );

        Key key = Keys.hmacShaKeyFor( Decoders.BASE64.decode( "guizhoumaotaojiu+zcl+hadoopcookbook+tigers+tigers" ) );

        String token = Jwts.builder().setSubject(String.valueOf(name))
                .claim("authorities", roles)
                .setExpiration(new Date(System.currentTimeMillis() + 10 * 60 * 60 * 1000))
                .signWith(key, SignatureAlgorithm.HS256).compact();

        writeJsonToResponse( response, "登录成功", token );
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
//        super.unsuccessfulAuthentication(request, response, failed);
        log.error( failed.getMessage() );
        writeJsonToResponse( response, "登录失败", null );
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res ) throws AuthenticationException, IOException, ServletException {
        Authentication a = new UsernamePasswordAuthenticationToken(
                req.getParameter( "user" ),
                req.getParameter( "password" ) );
        return this.getAuthenticationManager().authenticate( a );
    }

    /**
     * write back token to front with JSON format
     * @param resp
     * @param token
     */
    public void writeJsonToResponse( HttpServletResponse resp, String msg, String token ){
        JSONObject result = new JSONObject();
        result.put( "msg", msg );
        result.put( "method", "HttpServletResponse");
        if( token != null ) {
            result.put("token", token);
        }

        try (PrintWriter out = resp.getWriter()) {
            //设定类容为json的格式
            resp.setContentType( "application/json;charset=UTF-8" );
            //写到客户端
            out.write( result.toJSONString() );
            out.flush();
        } catch (IOException e) {
            log.error( e.getMessage() );
        }
    }
}
