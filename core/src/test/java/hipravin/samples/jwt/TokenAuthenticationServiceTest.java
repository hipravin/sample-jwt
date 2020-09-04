package hipravin.samples.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static hipravin.samples.jwt.TokenAuthenticationService.*;

class TokenAuthenticationServiceTest {
    @Test
    void sampleJwt() {
        String username = "pravin";

        String jwt = Jwts.builder()
                .setSubject(username)
                .claim(AUTHORITIES_CLAIM_KEY, "ROLE_ADMIN,ROLE_USER")
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();

        System.out.println(jwt);
    }
}