package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.JWTVerifier;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response.ResponseBuilder;
import org.json.JSONObject;

interface Account {
  ResponseBuilder changePassword(
      HttpSession httpSession, JSONObject jsonObject, JWTVerifier jwtVerifier);

  int logIn(String email, HttpSession httpSession, String password);

  int recover(Algorithm algorithm, String email);

  int signUp(Algorithm algorithm, HttpServletRequest httpServletRequest, JSONObject jsonObject);

  String verify(String email);
}
