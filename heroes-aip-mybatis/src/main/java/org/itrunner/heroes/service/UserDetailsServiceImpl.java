package org.itrunner.heroes.service;

import java.util.List;
import java.util.stream.Collectors;

import org.itrunner.heroes.dao.AuthorityDao;
import org.itrunner.heroes.dao.UsersDao;
import org.itrunner.heroes.dto.UsersCriteria;
import org.itrunner.heroes.dto.UsersDTO;
import org.itrunner.heroes.model.Authority;
import org.itrunner.heroes.model.User;
import org.itrunner.heroes.security.AuthorityUtil;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UsersDao usersDao;
    
    @Autowired
    private AuthorityDao authorityDao;

    @Override
    public UserDetails loadUserByUsername(String username) {
    	UsersCriteria criteria = new UsersCriteria();
    	criteria.createCriteria().andUsernameEqualTo(username);
    	List<UsersDTO> users = usersDao.selectByCriteria(criteria);
    	if(users.isEmpty()) {
    		throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
    	}
    	
        User user = new User();
        BeanUtils.copyProperties(users.get(0), user);
        List<Authority> authorities = getAuthorites(users.get(0).getId());
        user.setAuthorities(authorities);
        return create(user);
    }

    private List<Authority> getAuthorites(Long userId) {
    	
		return authorityDao.getAuthorites(userId).stream().map(dto->{
			Authority a = new Authority();
			BeanUtils.copyProperties(dto, a);
			return a;
		}).collect(Collectors.toList());
	}

	private static org.springframework.security.core.userdetails.User create(User user) {
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), AuthorityUtil.createGrantedAuthorities(user.getAuthorities()));
    }
}