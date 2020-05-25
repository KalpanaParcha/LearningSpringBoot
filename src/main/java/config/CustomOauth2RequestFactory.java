package config;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;

public class CustomOauth2RequestFactory extends DefaultOAuth2RequestFactory{

	@Autowired
	private TokenStore tokenStore;
	
	@Autowired
	private UserDetailsService  userDetailsService;
	
	public CustomOauth2RequestFactory(ClientDetailsService clientDetailsService) {
		// TODO Auto-generated constructor stub
		super(clientDetailsService);
	}
	
	@Override
	public TokenRequest createTokenRequest(Map<String, String> requestParameters, ClientDetails authenticatedClient) {
		// TODO Auto-generated method stub
		if(requestParameters.get("grant-type").equals("refresh-token")) {
			OAuth2Authentication authentication=tokenStore.readAuthenticationForRefreshToken(
					tokenStore.readRefreshToken(requestParameters.get("refresh-token")));
			SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(authentication.getName(), null,
					userDetailsService.loadUserByUsername(authentication.getName()).getAuthorities()));
		}
		return super.createTokenRequest(requestParameters, authenticatedClient);
	}
}
