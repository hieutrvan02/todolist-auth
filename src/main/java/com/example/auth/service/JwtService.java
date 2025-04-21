package com.example.auth.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "3Vf3CdFb6k9Yv3RDlzy8GpV4RmlsgfijyNARbD2+syQ=";

    private static final long ACCESS_TOKEN_VALIDITY_MS  = 1000 * 60 * 15;         // 15 minutes
    private static final long REQUEST_TOKEN_VALIDITY_MS = 1000 * 60 * 60 * 24;

    public String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long ttlMillis
    ) {
        long now = System.currentTimeMillis();
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + ttlMillis))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateAccessToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, ACCESS_TOKEN_VALIDITY_MS);
    }

    public String generateRequestToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "REQUEST");
        return buildToken(claims, userDetails, REQUEST_TOKEN_VALIDITY_MS);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public boolean isAccessTokenValid(String token, UserDetails userDetails) {
        return isTokenValid(token, userDetails)
                && !"REQUEST".equals(extractClaim(token, c -> c.get("type", String.class)));
    }

    public boolean isRequestTokenValid(String token, UserDetails userDetails) {
        return isTokenValid(token, userDetails)
                && "REQUEST".equals(extractClaim(token, c -> c.get("type", String.class)));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Jws<Claims> validateRequestToken(String token) {
        Jws<Claims> jws = Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token);

        String type = jws.getBody().get("type", String.class);
        if (!"REQUEST".equals(type)) {
            throw new JwtException("Token is not a request token");
        }
        return jws;
    }

    public Jws<Claims> validateAccessToken(String token) {
        Jws<Claims> jws = Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token);

        String type = jws.getBody().get("type", String.class);
        if ("REQUEST".equals(type)) {
            throw new JwtException("Token is not an access token");
        }
        return jws;
    }
}
