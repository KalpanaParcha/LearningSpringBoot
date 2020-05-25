package config;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import entity.Users;

public class CustomTokenEnhancer extends JwtAccessTokenConverter{

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		// TODO Auto-generated method stub
		
		Users user=(Users)authentication.getPrincipal();
		Map<String,Object> info=new LinkedHashMap<String,Object>(accessToken.getAdditionalInformation());
		info.put("email", user.getEmail());
		
		DefaultOAuth2AccessToken customeAccessToken=new  DefaultOAuth2AccessToken(accessToken);
		customeAccessToken.setAdditionalInformation(info);
		return super.enhance(accessToken, authentication);
	}
	
	
}
