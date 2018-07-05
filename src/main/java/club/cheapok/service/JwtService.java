package club.cheapok.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

import javax.servlet.http.Cookie;
import java.io.UnsupportedEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static java.util.Arrays.stream;

public class JwtService {

    private static final int MAX_MINUTES = 15;

    public static final int MAX_SECONDS = MAX_MINUTES * 60;

    public static final String JWT_TOKEN = "jwt_token";

    private Algorithm algorithm;

    public JwtService() {
        try {
            algorithm = Algorithm.HMAC256("secret");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public String createToken(final String username) {
        return JWT.create()
                  .withHeader(Map.of("alg", "HS256", "typ", "JWT"))
                  .withSubject("123456")
                  .withIssuer("cheapok")
                  .withExpiresAt(Date.from(Instant.now().plus(Duration.ofMinutes(MAX_MINUTES))))
                  .withClaim("username", username)
                  .sign(algorithm);
    }

    public boolean verifyToken(final String token) {
        try {
            JWT.require(algorithm)
               .withIssuer("cheapok")
               .build()
               .verify(token);
            return true;
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    public String findJwtToken(final Cookie[] cookies) {
        String jwtToken = null;
        if (cookies != null) {
            jwtToken = stream(cookies)
                    .filter(c -> JWT_TOKEN.equals(c.getName()))
                    .findFirst()
                    .map(Cookie::getValue)
                    .orElse(null);
        }
        return jwtToken;
    }
}
