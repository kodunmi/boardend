package com.boardend.boardend.security.services;

import com.boardend.boardend.models.MobileUser;
import com.boardend.boardend.repository.MobileUserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.boardend.boardend.models.User;
import com.boardend.boardend.models.Rider;
import com.boardend.boardend.repository.UserRepository;
import com.boardend.boardend.repository.RiderRepository;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;
    private final RiderRepository riderRepository;
    private final MobileUserRepository mobileUserRepository;
    private final ModelMapper mapper;

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElse(null);

        if (user != null) {
            return mapper.map(user, UserDetailsImpl.class);
        }

        Rider rider = riderRepository.findByUsernameIgnoreCase(username).orElse(null);

        if (rider != null) {
            return new RiderDetailsImpl(rider);
        }

        MobileUser mobileUser = mobileUserRepository.findByUsernameIgnoreCase(username).orElse(null);

        if (mobileUser != null) {
            return new MobileUserDetailsImpl(mobileUser);
        }

        throw new UsernameNotFoundException("User Not Found with username: " + username);
    }


}
