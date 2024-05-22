package com.example.oauth2jwt.service;

import com.example.oauth2jwt.dto.*;
import com.example.oauth2jwt.entity.UserEntity;
import com.example.oauth2jwt.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthorizationException { //파라미터는 리소스 서버에서 제공하는 유저 정보
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if(registrationId.equals("naver")) { //naver에 관한 처리
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        }
        else if(registrationId.equals("google")) { //google에 관한 처리
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }
        else {
            return null;
        }

        //리소스 서버에서 발급 받은 정보로 사용자를 특정할 아이디값을 만듬. 리소스 서버에서 제공한 값은 해당 유저들이 겹칠 수 있어, 특정하게 우리서버에서 관리할 수 있는 유저 id값을 만든다
        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();
        UserEntity existData = userRepository.findByUsername(username);
        if(existData == null) { //한번도 로그인 한 적 없는 유저
            UserEntity userEntity = new UserEntity(); //객체 하나 생성
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setName(oAuth2Response.getName());
            userEntity.setRole("ROLE_USER");

            userRepository.save(userEntity); //DB에 저장

            UserDto userDto = new UserDto();
            userDto.setUsername(username);
            userDto.setName(oAuth2Response.getName());
            userDto.setRole("ROLE_USER");

            return new CustomOAuth2User(userDto);
        }
        else { //한번이라도 로그인 한 적 있는 유저
            existData.setEmail(oAuth2Response.getEmail()); //이메일 바뀐 것 확인
            existData.setName(oAuth2Response.getName()); //이름 바뀐 것 확인

            userRepository.save(existData); //DB에 저장

            UserDto userDto = new UserDto();
            userDto.setUsername(existData.getUsername());
            userDto.setName(oAuth2Response.getName()); //existData.getName()이 아닌 이유: 이름 바뀐 경우, 바뀐 값을 가져와야 하므로
            userDto.setRole(existData.getRole());

            return new CustomOAuth2User(userDto);
        }
    }
}
