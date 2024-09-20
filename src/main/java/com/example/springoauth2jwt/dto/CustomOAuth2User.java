package com.example.springoauth2jwt.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {

    private final UserDTO userDTO;
    public CustomOAuth2User(UserDTO userDTO) {
        this.userDTO = userDTO;
    }

    @Override
    public Map<String, Object> getAttributes() {
        // 구글에서 사용하는 Attributes랑 네이버에서 사용하는 Attributes랑 달라 획일화하기 까다로워서 사용 X
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {
                return userDTO.getRole();
            }
        });

        return collection;

    }

    @Override
    public String getName() {
        return userDTO.getName();
    }

    public String getUsername() {

        return userDTO.getUsername();
    }
}
