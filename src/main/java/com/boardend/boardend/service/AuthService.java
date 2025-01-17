package com.boardend.boardend.service;

import com.boardend.boardend.exception.DisabledException;
import com.boardend.boardend.exception.UserNotApprovedException;
import com.boardend.boardend.exception.UserNotFoundException;
import com.boardend.boardend.models.Rider;
import com.boardend.boardend.models.Status;
import com.boardend.boardend.models.User;
import com.boardend.boardend.payload.request.LoginRequest;
import com.boardend.boardend.payload.response.JwtResponse;
import com.boardend.boardend.repository.RiderRepository;
import com.boardend.boardend.repository.UserRepository;
import com.boardend.boardend.security.jwt.JwtUtils;
import com.boardend.boardend.security.services.RefreshTokenService;
import com.boardend.boardend.security.services.RiderDetailsImpl;
import com.boardend.boardend.security.services.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtUtils jwtUtils;
    private final ModelMapper modelMapper;
    private final RiderRepository riderRepository;

    public JwtResponse loginUser(LoginRequest loginRequest) {
        Optional<User> optionalUser = userRepository.findByUsername(loginRequest.getUsername());
        if (optionalUser.isEmpty()) throw new UserNotFoundException("User not found.");
        User user = optionalUser.get();
        if (user.getStatus() == Status.DISABLED)
            throw new DisabledException("Your account has been disabled. Please contact support.");
        if (user.getStatus() == Status.NOT_APPROVED)
            throw new UserNotApprovedException("User not approved.");

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        log.info("userDetails : {}", userDetails);
        JwtResponse jwtResponse = modelMapper.map(userDetails, JwtResponse.class);
        jwtResponse.setToken(jwtUtils.generateJwtToken(authentication));
        jwtResponse.setRefreshToken(refreshTokenService.createRefreshTokenForUser(userDetails.getId()).getToken());
        return jwtResponse;
    }

    public JwtResponse loginRider(LoginRequest loginRequest) {
        Optional<Rider> optionalRider = riderRepository.findByUsernameIgnoreCase(loginRequest.getUsername());
        if (optionalRider.isEmpty()) throw new UserNotFoundException("User not found.");
        Rider rider = optionalRider.get();
        if (rider.getStatus() == Status.DISABLED)
            throw new DisabledException("Your account has been disabled. Please contact support.");
        if (rider.getStatus() == Status.NOT_APPROVED)
            throw new UserNotApprovedException("User not approved.");
        if (rider.getStatus() == Status.DISABLED) {
            throw new UserNotApprovedException("This account has been locked by your administrator. Kindly contact them for further assistance.");
        }
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        RiderDetailsImpl riderDetails = (RiderDetailsImpl) authentication.getPrincipal();
        log.info("userDetails : {}", riderDetails);
        JwtResponse jwtResponse = modelMapper.map(riderDetails, JwtResponse.class);
        jwtResponse.setToken(jwtUtils.generateJwtToken(authentication));
        jwtResponse.setRefreshToken(refreshTokenService.createRefreshTokenForRider(riderDetails.getId()).getToken());
        return jwtResponse;
    }
}
