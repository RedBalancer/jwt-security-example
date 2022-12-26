package com.xyz.jwtwithspring.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.Key;
import java.util.List;

/**
 * @author Chunlong Zhang
 * @version 1.0.0
 * @ClassName JwtAuthorizationFilter.java
 * @Description 授权用Filter（检查用户身份是否具有访问权限）
 * @createTime 2022年12月19日 19:14:00
 */
@Slf4j
public class JwtAuthorizationFilter extends GenericFilterBean {

    /**
     * 当没有取到header中的jwt token时，应该走既有的filter chain。而不是返回异常。
     * @param requ
     * @param resp
     * @param filterChain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest requ, ServletResponse resp, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = ( HttpServletRequest ) requ;
        String jwtToken = req.getHeader("authorization");
        if( jwtToken == null || jwtToken.split( " " ).length != 2 ) {
            log.error( "Error jwtToken: " + jwtToken );
            throw new ServletException( "用户Token内容无效！" );
        }
        log.info( "jwtToken: " + jwtToken );

        // 解析用户request 头中的token
        Key key = Keys.hmacShaKeyFor( Decoders.BASE64.decode( "guizhoumaotaojiu+zcl+hadoopcookbook+tigers+tigers" ) );
        Jwt parse = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws( jwtToken.split( " " )[1] );
        Claims body = ( Claims ) parse.getBody();
        String userName = body.getSubject();
        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(String.valueOf(body.get("authorities")));
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userName, null, authorities);
        SecurityContextHolder.getContext().setAuthentication( usernamePasswordAuthenticationToken );

        filterChain.doFilter( requ, resp );
    }
}
