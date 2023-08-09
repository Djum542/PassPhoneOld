package com.gdu.nhom1.shopproject.jwt;

import com.gdu.nhom1.shopproject.models.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import java.util.Date;

public class JwtTokenUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenUtil.class);

    private static final long EXPIRE_DURATION = 24 * 60 * 60 * 1000; // 24 hour
    @Value("${app.jwt.secet}")
    private String SECRET_KEY;
    public String generaAccessToken(User user){
        return Jwts.builder()
                .setSubject(String.format("%s,%s", user.getId(), user.getEmail()))
                .setIssuer("CodeJava")
                .claim("roles", user.getRoles().toString())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE_DURATION))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }
    public  boolean validateAccessToken(String token){
        try {
            Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token);
            return true;
        }catch (ExpiredJwtException e){
            LOGGER.error("JWT expried", e.getMessage());
        }catch (IllegalArgumentException ex){
            LOGGER.error("Token is null, empty or only whitesapp", ex.getMessage());
        }catch (MalformedJwtException e){
            LOGGER.error("Jwt is invalid");
        }catch (UnsupportedJwtException e){
            LOGGER.error("JWT is not suppoted", e.getMessage());
        }catch (SignatureException e){
            LOGGER.error("Signature validation failed");
        }
        return false;
    }
    public String getSubject(String token){
        return parseClaims(token).getSubject();
    }
    public Claims parseClaims(String token){
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }
}
