package club.cheapok.servlet;

import club.cheapok.service.JwtService;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static club.cheapok.service.JwtService.JWT_TOKEN;
import static club.cheapok.service.JwtService.MAX_SECONDS;
import static java.util.Objects.isNull;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {

    private JwtService jwtService;

    @Override
    public void init() throws ServletException {
        super.init();
        jwtService = new JwtService();
    }

    @Override
    protected void doGet(final HttpServletRequest req,
                         final HttpServletResponse resp)
            throws ServletException, IOException {
        if (isNull(jwtService.findJwtToken(req.getCookies()))) {
            req.getRequestDispatcher("/login.jsp").forward(req, resp);
            return;
        }
        
        resp.sendRedirect("/main");
    }

    @Override
    protected void doPost(final HttpServletRequest req,
                          final HttpServletResponse resp)
            throws ServletException, IOException {

        final String username = req.getParameter("username");
        final String password = req.getParameter("password");

        if ("valera".equals(username) && "partizan".equals(password)) {
            final Cookie jwtCookie = new Cookie(JWT_TOKEN, jwtService.createToken(username));
            jwtCookie.setMaxAge(MAX_SECONDS);
            resp.addCookie(jwtCookie);
            resp.sendRedirect(req.getContextPath() + "/main");
            return;
        }
        doGet(req, resp);
    }
}
