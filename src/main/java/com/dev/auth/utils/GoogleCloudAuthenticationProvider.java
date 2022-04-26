package com.dev.auth.utils;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Component
public class GoogleCloudAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = String.valueOf(authentication.getPrincipal());
        String password = String.valueOf(authentication.getCredentials());

        User userFromGoogleCloud = getUserFromGoogleCloud(username, password);

        if (userFromGoogleCloud != null) {
            return new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());
        }

        throw new BadCredentialsException("Error");
    }

    private User getUserFromGoogleCloud(String username, String password) {
        Map<String, String> map = new HashMap<>();
        map.put("dev1", "1234");
        if (map.containsKey(username) && map.get(username).equals(password)) {
            return new User(username, password, new ArrayList<>());
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}
