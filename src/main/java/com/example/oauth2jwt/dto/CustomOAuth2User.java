package com.example.oauth2jwt.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {

    private final UserDto userDto;

    public CustomOAuth2User(UserDto userDto) {
        this.userDto = userDto;
    }


    @Override
    public Map<String, Object> getAttributes() { //username 데이터값 리턴해줌. 네이버에서 받은 값과 구글에서 받은 response값이 다르므로 우리가 따로 getUsername메소드를 만들자
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { //role값 리턴해줌

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {

                return userDto.getRole();
            }
        });
        return collection;
    }

    @Override
    public String getName() {
        return userDto.getName();
    }

    public String getUsername() {
        return userDto.getUsername();
    }
}
