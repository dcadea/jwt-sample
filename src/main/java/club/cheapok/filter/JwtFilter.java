package club.cheapok.filter;

import club.cheapok.service.JwtService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static club.cheapok.service.JwtService.JWT_TOKEN;
import static java.util.Objects.isNull;

@WebFilter("/*")
public class JwtFilter extends HttpFilter {

    private JwtService jwtService;


    @Override
    public void init() throws ServletException {
        super.init();
        jwtService = new JwtService();
    }

    @Override
    protected void doFilter(final HttpServletRequest req,
                            final HttpServletResponse resp,
                            final FilterChain chain) throws IOException, ServletException {
        final String jwtToken = jwtService.findJwtToken(req.getCookies());

        if (isNull(jwtToken)) {
            req.getRequestDispatcher("/login").forward(req, resp);
        } else if (jwtService.verifyToken(jwtToken)) {
            chain.doFilter(req, resp);
        } else {
            final Cookie clearJwt = new Cookie(JWT_TOKEN, "");
            clearJwt.setMaxAge(0);
            resp.addCookie(clearJwt);

            resp.setHeader("Refresh", "5;url=/login");
            req.getRequestDispatcher("/error.jsp").forward(req, resp);
        }
    }
}
