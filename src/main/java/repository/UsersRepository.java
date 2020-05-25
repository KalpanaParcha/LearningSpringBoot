package repository;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import entity.Users;

@Transactional
@Repository
public interface UsersRepository extends JpaRepository<Users, Long>{
	Users findByUserName(String username);
}
