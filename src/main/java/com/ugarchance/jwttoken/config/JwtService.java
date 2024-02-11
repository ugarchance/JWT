package com.ugarchance.jwttoken.config;


import io.jsonwebtoken.Claims;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Service
public class JwtService {

    //256 bit hash key http://network-logix.net/
    private static final String SECRET_KEY = "4b663438745c6c75386e4e6b3c6c71307c34312f5c747d227c5e3153655a6243";

    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        //tokeni claimlere parçaladım
        final Claims claims = extractAllClaims(token);
        // çıkarılan claimler arasında gelen claime ulaşır ve buna göre değer döndürür
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))//when this claim created
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))//geçerlilik süresi 1 gün boyunca
                .signWith(getSignInKey(), Jwts.SIG.HS256)//signature algorithm
                .compact();
    }

    public boolean isTokenValid(String token , UserDetails userDetails ){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()))&&!isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    //bir jwt tokenindan tüm claimleri(talepleri) ayırır
    private Claims extractAllClaims(String token) {
//        return Jwts
//                .parserBuilder() bunun yerine parser
//                .setSigningKey(getSignInKey())
//                .build()
//                .parseClaimsJws(token) bunun yerine parseSingedClaims
//                .getBody(); // bunun yerine getPayload Geliyor

        return Jwts
                .parser() //create parser object
                //eski kullanımı setSigningKey(getSignInKey()
                .verifyWith(getSignInKey())//indicates where to get the signature key
                //imza anahtarının nerden alıncağını işaret eder
                .build()
                .parseSignedClaims(token)//the function parsing token and verifies token signature
                .getPayload();//get the token last situation
    }


    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);//HMAC (Hash-based Message Authentication Code) SHA (Secure Hash Algorithm

    }
   /*
    Eski kullanımı
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);//HMAC (Hash-based Message Authentication Code) SHA (Secure Hash Algorithm
        }*/
}
