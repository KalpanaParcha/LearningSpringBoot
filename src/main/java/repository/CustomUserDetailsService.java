package repository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import entity.Users;

@Service(value = "userDetailsService")
public class CustomUserDetailsService implements UserDetailsService{

	@Autowired
	private UsersRepository usersRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) {
		// TODO Auto-generated method stub
		Users users=usersRepository.findByUserName(username);
		if(users==null) {
			throw new BadCredentialsException("Bad Credentials");
		}
		
		new AccountStatusUserDetailsChecker().check(users);
		return users;
	}
}
