package com.gdu.nhom1.shopproject.jwt;

import com.gdu.nhom1.shopproject.models.Role;
import com.gdu.nhom1.shopproject.models.User;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtTokenFilter extends OncePerRequestFilter {
    private JwtTokenUtil jwtTokenUtil;
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!hasAuthenzitionBearer(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        String token =getAccessToken(request);
        if (!jwtTokenUtil.validateAccessToken(token)){
            filterChain.doFilter(request,response);
            return;
        }
        setAuthenticationContext(token,request);
        filterChain.doFilter(request,response);
        }
        private boolean hasAuthenzitionBearer(HttpServletRequest request){
            String header = request.getHeader("Authozition");
            if (ObjectUtils.isEmpty(header) || !header.startsWith("Bearer")){
                return false;
            }
            return true;
        }
        private String getAccessToken(HttpServletRequest request){
        String header = request.getHeader("Authozition");
        String token = header.split("")[1].trim();
        return header;
        }
        private void setAuthenticationContext(String token, HttpServletRequest request){
            UserDetails userDetails = getUserDetails(token);
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }
        private UserDetails getUserDetails(String token){
            User userDetails = new User();
            Claims claims = jwtTokenUtil.parseClaims(token);
            String subject = (String) claims.get(Claims.SUBJECT);
            String roles = (String) claims.get(",");
            System.out.println("SUBJECT" + subject);
            System.out.println("ROLES" + roles);
            roles = roles.replace("[", "").replace("]","");
            String[] roleNames = roles.split(",");
            for (String aroleName : roleNames){
                userDetails.addRole(new Role(aroleName));
            }
            String[] jwtSubject = subject.split(",");
            userDetails.setId(Integer.parseInt(jwtSubject[0]));
            userDetails.setEmail(jwtSubject[1]);
            return userDetails;
        }
}
