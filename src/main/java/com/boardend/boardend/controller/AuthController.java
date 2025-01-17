package com.boardend.boardend.controller;

import java.io.UnsupportedEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import javax.validation.Valid;

import com.boardend.boardend.exception.*;
import com.boardend.boardend.models.*;
import com.boardend.boardend.payload.request.*;
import com.boardend.boardend.payload.response.TokenRefreshResponse;
import com.boardend.boardend.repository.MobileUserRepository;
import com.boardend.boardend.repository.RiderRepository;
import com.boardend.boardend.security.services.MobileUserDetailsImpl;
import com.boardend.boardend.security.services.RefreshTokenService;
import com.boardend.boardend.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;


import com.boardend.boardend.payload.response.JwtResponse;
import com.boardend.boardend.payload.response.MessageResponse;
import com.boardend.boardend.repository.UserRepository;
import com.boardend.boardend.security.jwt.JwtUtils;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*") // Allow access from any origin
public class AuthController {

        @Autowired
        AuthenticationManager authenticationManager;

        @Autowired
        UserRepository userRepository;

        @Autowired
        RiderRepository riderRepository;

        @Autowired
        PasswordEncoder encoder;

        @Autowired
        JwtUtils jwtUtils;

        @Autowired
        RefreshTokenService refreshTokenService;

        @Autowired
        User user;
        @Autowired
        private MobileUserRepository mobileUserRepository;

        private final AuthService service;
    @Autowired
    private AuthService authService;

        @PostMapping("/signin")
        public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) throws AuthenticationException {
                return ResponseEntity.ok(service.loginUser(loginRequest));
        }

        @PostMapping("/signup")
        public ResponseEntity<?> createCompany(@Valid @RequestBody SignupRequest signUpRequest) {
                if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                        return ResponseEntity.badRequest()
                                .body(new MessageResponse("Error: Username is already taken!"));
                }

                if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                        return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
                }

                sendApprovalEmail(signUpRequest.getEmail(), signUpRequest.getCompanyName());


                // Create new user's account
                User newUser = new User(
//                        signUpRequest.getCompanyName(),
//                        signUpRequest.getUsername(), signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()), signUpRequest.getCacNumber(),
//                        signUpRequest.getStreetAddress(), signUpRequest.getCompanyState(), signUpRequest.getRiderNumber(), signUpRequest.getAccountNumber(), signUpRequest.getBankName(),
//                        Status.NOT_APPROVED
                );
                userRepository.save(newUser);


                return ResponseEntity.ok(new MessageResponse("Your Account has been created. Awaiting approval."));
        }

        private void sendApprovalEmail(String email, String companyName) {
                String subject = "Welcome to Rubi Logistics";
                String body = "<html>" +
                        "<head>" +
                        "<style>" +
                        "body { font-family: Arial, sans-serif; background-color: #f2f2f2; }" +
                        ".container { max-width: 600px; margin: 0 auto; padding: 20px; }" +
                        ".header { background-color: #ffffff; text-align: center; padding: 20px; }" +
                        ".logo { max-width: 200px; }" +
                        ".content { background-color: #ffffff; padding: 20px; }" +
                        "h1 { color: #333333; font-size: 24px; margin-bottom: 20px; }" +
                        "p { color: #555555; font-size: 16px; margin-bottom: 10px; }" +
                        "</style>" +
                        "</head>" +
                        "<body>" +
                        "<div class='container'>" +
                        "<div class='header'>" +
                        "<img class='logo' src='https://i.ibb.co/0GX70CY/Photo-from-Gray.jpg' alt='Logo'>" +
                        "</div>" +
                        "<div class='content'>" +
                        "<h1>Welcome to Rubi Logistics</h1>" +
                        "<p>Hello " + companyName + ",</p>" +
                        "<p>Thank you for signing up! Your account is currently awaiting approval. Please try the platform within the next 12 hours to find out if you have been accepted or refused.</p>" +
                        "<p>If you didn't sign up using this email, or you feel your email has been compromised, kindly report it to this address:</p>" +
                        "<p>support@rubidelivery.com</p>" +
                        "<p>Regards, the Rubi Logistics Team</p>" +
                        "</div>" +
                        "</div>" +
                        "</body>" +
                        "</html>";
                Properties props = new Properties();
                props.put("mail.smtp.host", "smtp.gmail.com");
                props.put("mail.smtp.port", "587");
                props.put("mail.smtp.auth", "true");
                props.put("mail.smtp.starttls.enable", "true");

                Session session = Session.getInstance(props, new Authenticator() {
                        protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication("jmrubinusltd@gmail.com", "udnafhivdjqzelez");
                        }
                });

                try {
                        Message message = new MimeMessage(session);
                        message.setFrom(new InternetAddress(email, "Rubi Logistics"));
                        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(email));
                        message.setSubject(subject);
                        message.setContent(body, "text/html");


                        Transport.send(message);

                } catch (MessagingException e) {
                        throw new RuntimeException(e);
                } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException(e);
                }
        }

        @PostMapping("/rider/signup")
        public ResponseEntity<?> createRider(@Valid @RequestBody RiderSignupRequest signUpRequest) {
                // Check if the username is already taken
                if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                        return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
                }

                // Check if the email is already in use
                if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                        return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
                }

                // Retrieve the authenticated user (admin) from the JWT token
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                String adminUsername = authentication.getName();
                User adminUser = userRepository.findByUsername(adminUsername).orElse(null);

                // If the admin user is not found, handle the error as needed
                if (adminUser == null) {
                        return ResponseEntity.badRequest().body(new MessageResponse("Error: Admin user not found!"));
                }

                // Check if a rider with the given username already exists
                if (riderRepository.existsByUsername(signUpRequest.getUsername())) {
                        return ResponseEntity.badRequest().body(new MessageResponse("Error: Rider account already exists!"));
                }

                // Check if the rider's vehicle number and phone number are the same separately
                if (signUpRequest.getVehicleNumber().equals(signUpRequest.getPhone())) {
                        return ResponseEntity.badRequest().body(new MessageResponse("Error: Vehicle number and phone number cannot be the same!"));
                }

                // Check if the rider's vehicle number already exists
                if (riderRepository.existsByVehicleNumber(signUpRequest.getVehicleNumber())) {
                        return ResponseEntity.badRequest().body(new MessageResponse("Error: Vehicle number is already in use!"));
                }

                // Check if the rider's phone number already exists
                if (riderRepository.existsByPhone(signUpRequest.getPhone())) {
                        return ResponseEntity.badRequest().body(new MessageResponse("Error: Phone number is already in use!"));
                }

                // Create the rider associated with the admin user
                Rider newRider = new Rider(signUpRequest.getName(), signUpRequest.getPhone(),
                        signUpRequest.getStreetAddress(), signUpRequest.getEmail(), signUpRequest.getUsername(),
                        encoder.encode(signUpRequest.getPassword()), signUpRequest.getVehicleNumber(), signUpRequest.getCompanyState(), signUpRequest.getCompanyName(), true, Status.APPROVED);

                // Set the relationship between rider and admin
                newRider.setUser(adminUser);
                riderRepository.save(newRider);

                return ResponseEntity.ok(new MessageResponse("Rider Account has been created successfully."));
        }

        @PostMapping("/rider/signin")
        public ResponseEntity<?> authenticateRider(@Valid @RequestBody LoginRequest loginRequest) throws Exception {
                 return ResponseEntity.ok(authService.loginRider(loginRequest));
        }


        @PostMapping("/refreshtoken")
        public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
                String requestRefreshToken = request.getRefreshToken();

                return refreshTokenService.findByToken(requestRefreshToken)
                        .map(refreshTokenService::verifyExpiration)
                        .map(RefreshToken::getUser)
                        .map(user -> {
                                String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                                return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                        })
                        .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                                "Refresh token is not in database!"));
        }

        @PostMapping("/forgot")
        public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
                Optional<User> optionalUser = userRepository.findByEmail(request.getEmail());

                if (optionalUser.isPresent()) {
                        User user = optionalUser.get();

                        // Generate a reset token (you can use a utility class or library for this)
                        String resetToken = generateResetToken();

                        // Save the reset token to the user's account (you may need to add a new field in the User entity)
                        user.setResetToken(resetToken);
                        userRepository.save(user);

                        // Send the reset instructions email
                        sendResetInstructionsEmail(user.getEmail(), user.getCompanyName(), resetToken);

                        return ResponseEntity.ok(new MessageResponse("Password reset instructions sent successfully."));
                } else {
                        // User not found with the provided email
                        return ResponseEntity.badRequest().body(new MessageResponse("User not found."));
                }
        }

        private String generateResetToken() {
                return UUID.randomUUID().toString();
        }

        private void sendResetInstructionsEmail(String email, String resetToken, String companyName) {
                String subject = "Reset your Rubi Logistics Password";
                String body = "<html>" +
                        "<head>" +
                        "<style>" +
                        "body { font-family: Arial, sans-serif; background-color: #f2f2f2; }" +
                        ".container { max-width: 600px; margin: 0 auto; padding: 20px; }" +
                        ".header { background-color: #ffffff; text-align: center; padding: 20px; }" +
                        ".logo { max-width: 200px; }" +
                        ".content { background-color: #ffffff; padding: 20px; }" +
                        "h1 { color: #333333; font-size: 24px; margin-bottom: 20px; }" +
                        "p { color: #555555; font-size: 16px; margin-bottom: 10px; }" +
                        "</style>" +
                        "</head>" +
                        "<body>" +
                        "<div class='container'>" +
                        "<div class='header'>" +
                        "<img class='logo' src='https://i.ibb.co/0GX70CY/Photo-from-Gray.jpg' alt='Logo'>" +
                        "</div>" +
                        "<div class='content'>" +
                        "<h1>Welcome to Rubi Logistics</h1>" +
                        "<p>Hello " + companyName + ",</p>" +
                        "<p>You have requested to reset your password. The link expires in ten minutes. Please click on the link below to reset your password:</p>" +
                        "<p><a href='https://dashboard.rubidelivery.com/reset?token=" + resetToken + "'>Reset Your Password</a></p>" +
                        "<p>If you didn't request a password reset, please ignore this email.</p>" +
                        "<p>Regards, the Rubi Logistics Team</p>" +
                        "</div>" +
                        "</div>" +
                        "</body>" +
                        "</html>";


                Properties props = new Properties();
                props.put("mail.smtp.host", "smtp.gmail.com");
                props.put("mail.smtp.port", "587");
                props.put("mail.smtp.auth", "true");
                props.put("mail.smtp.starttls.enable", "true");

                Session session = Session.getInstance(props, new Authenticator() {
                        protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication("jmrubinusltd@gmail.com", "udnafhivdjqzelez");
                        }
                });

                try {
                        Message message = new MimeMessage(session);
                        message.setFrom(new InternetAddress(email, "Rubi Logistics"));
                        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(email));
                        message.setSubject(subject);
                        message.setContent(body, "text/html");


                        Transport.send(message);

                } catch (MessagingException e) {
                        throw new RuntimeException(e);
                } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException(e);
                }
        }
        @PostMapping("/reset")
        public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
                // Retrieve the user based on the reset token
                Optional<User> optionalUser = userRepository.findByResetToken(request.getResetToken());
                if (optionalUser.isPresent()) {
                        User user = optionalUser.get();

                        // Validate the reset token (optional step)
                        if (isResetTokenValid(user, request.getResetToken())) {
                                // Update the user's password with the new one provided
                                String newPassword = encoder.encode(request.getNewPassword());
                                user.setPassword(newPassword);

                                // Reset the reset token to null since it has been used
                                user.setResetToken(null);

                                // Save the updated user to the database
                                userRepository.save(user);

                                return ResponseEntity.ok(new MessageResponse("Password reset successfully."));
                        } else {
                                return ResponseEntity.badRequest().body(new MessageResponse("Invalid reset token."));
                        }
                } else {
                        return ResponseEntity.badRequest().body(new MessageResponse("User not found or invalid reset token."));
                }
        }
        private boolean isResetTokenValid(User user, String resetToken) {
                // Compare the reset token stored in the user object with the one provided in the request
                boolean tokensMatch = resetToken.equals(user.getResetToken());

                // Check if the token is still within a valid timeframe (e.g., token expiration)
                boolean isValidTimeframe = isTokenWithinValidTimeframe(user.getResetTokenExpiration());

                // Add any additional checks, such as token expiration or usage limits
                // ...

                return tokensMatch && isValidTimeframe;
        }
        private boolean isTokenWithinValidTimeframe(Instant expiration) {
                // Compare the token expiration timestamp with the current time
                Instant currentTime = Instant.now();

                // Set the validity timeframe to 10 minutes
                Duration validityDuration = Duration.ofMinutes(10);
                Instant validTimeframe = expiration.plus(validityDuration);

                // Return true if the current time is before the valid timeframe, indicating the token is still valid
                // Return false if the current time is after or equal to the valid timeframe, indicating the token has expired

                return currentTime.isBefore(validTimeframe);
        }

@PostMapping("/mobile/signin")
public ResponseEntity<?> authenticateMobileUser(@Valid @RequestBody LoginRequest loginRequest) {
        Optional<MobileUser> optionalUser = mobileUserRepository.findByUsernameIgnoreCase(loginRequest.getUsername());
        if (optionalUser.isPresent()) {
                MobileUser user = optionalUser.get();

                // Check if OTP exists for the user
                if (user.getOtp() != null) {
                        return ResponseEntity
                                .badRequest()
                                .body(new MessageResponse("Please verify this account first"));

                }

                // Continue with the login process since the user has verified the OTP
                Authentication authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                String jwt = jwtUtils.generateJwtToken(authentication);

                MobileUserDetailsImpl userDetails = new MobileUserDetailsImpl(user);
                List<String> roles = userDetails.getAuthorities()
                        .stream()
                        .map(item -> item.getAuthority())
                        .collect(Collectors.toList());

                RefreshToken refreshToken = refreshTokenService.createRefreshTokenForMobileUser(userDetails.getId());

                JwtResponse mobileJwtResponse = new JwtResponse(
//                        jwt,
//                        refreshToken.getToken(),
//                        userDetails.getId(),
//                        userDetails.getName(),
//                        userDetails.getUsername(),
//                        userDetails.getEmail(),
//                        userDetails.getPhone(),
//                        roles
                );

                return ResponseEntity.ok(mobileJwtResponse);
        } else {
                return ResponseEntity
                        .badRequest()
                        .body(new MessageResponse("This account does not exist"));
        }
}


        @PostMapping("/mobile/reset")
        public ResponseEntity<?> resetMobilePassword(@RequestBody ResetPasswordRequest request) {
                // Retrieve the user based on the reset token
                Optional<MobileUser> optionalUser = mobileUserRepository.findByResetToken(request.getResetToken());
                if (optionalUser.isPresent()) {
                        MobileUser user = optionalUser.get();

                        // Validate the reset token (optional step)
                        if (isResetTokenValidMobile(user, request.getResetToken())) {
                                // Update the user's password with the new one provided
                                String newPassword = encoder.encode(request.getNewPassword());
                                user.setPassword(newPassword);

                                // Reset the reset token to null since it has been used
                                user.setResetToken(null);

                                // Save the updated user to the database
                                mobileUserRepository.save(user);

                                return ResponseEntity.ok(new MessageResponse("Password reset successfully."));
                        } else {
                                return ResponseEntity.badRequest().body(new MessageResponse("Invalid reset token."));
                        }
                } else {
                        return ResponseEntity.badRequest().body(new MessageResponse("User not found or invalid reset token."));
                }
        }

        private boolean isResetTokenValidMobile(MobileUser user, String resetToken) {
                // Compare the reset token stored in the user object with the one provided in the request
                boolean tokensMatch = resetToken.equals(user.getResetToken());

                // Check if the token is still within a valid timeframe (e.g., token expiration)
                boolean isValidTimeframe = isTokenWithinValidTimeframe(user.getResetTokenExpiration());

                // Add any additional checks, such as token expiration or usage limits
                // ...

                return tokensMatch && isValidTimeframe;
        }

        @PostMapping("/mobile/forgot")
        public ResponseEntity<?> forgotPasswordMobile(@RequestBody ForgotPasswordRequest request) {
                Optional<MobileUser> optionalUser = mobileUserRepository.findByEmail(request.getEmail());

                if (optionalUser.isPresent()) {
                        MobileUser user = optionalUser.get();

                        // Generate a reset token (you can use a utility class or library for this)
                        String resetToken = generateResetToken();

                        // Save the reset token to the user's account (you may need to add a new field in the User entity)
                        user.setResetToken(resetToken);
                        mobileUserRepository.save(user);

                        // Send the reset instructions email
                        sendResetInstructionsEmailMobile(user.getEmail(), user.getName(), resetToken);

                        return ResponseEntity.ok(new MessageResponse("Password reset instructions sent successfully."));
                } else {
                        // User not found with the provided email
                        return ResponseEntity.badRequest().body(new MessageResponse("User not found."));
                }
        }

        private String generateResetTokenMobile() {
                return UUID.randomUUID().toString();
        }

        private void sendResetInstructionsEmailMobile(String email, String name, String resetToken) {
                String subject = "Reset your Rubi Logistics Password";
                String body = "<html>" +
                        "<head>" +
                        "<style>" +
                        "body { font-family: Arial, sans-serif; background-color: #f2f2f2; }" +
                        ".container { max-width: 600px; margin: 0 auto; padding: 20px; }" +
                        ".header { background-color: #ffffff; text-align: center; padding: 20px; }" +
                        ".logo { max-width: 200px; }" +
                        ".content { background-color: #ffffff; padding: 20px; }" +
                        "h1 { color: #333333; font-size: 24px; margin-bottom: 20px; }" +
                        "p { color: #555555; font-size: 16px; margin-bottom: 10px; }" +
                        "</style>" +
                        "</head>" +
                        "<body>" +
                        "<div class='container'>" +
                        "<div class='header'>" +
                        "<img class='logo' src='https://i.ibb.co/0GX70CY/Photo-from-Gray.jpg' alt='Logo'>" +
                        "</div>" +
                        "<div class='content'>" +
                        "<h1>Rubi Logistics Password Reset</h1>" +
                        "<p>Hello " + name + ",</p>" +
                        "<p>You have requested to reset your password. The link expires in ten minutes. Please click on the link below to reset your password:</p>" +
                        "<p><a href='https://dashboard.rubidelivery.com/reset?token=" + resetToken + "'>Reset Your Password</a></p>" +
                        "<p>If you didn't request a password reset, please ignore this email.</p>" +
                        "<p>Regards, the Rubi Logistics Team</p>" +
                        "</div>" +
                        "</div>" +
                        "</body>" +
                        "</html>";


                Properties props = new Properties();
                props.put("mail.smtp.host", "smtp.gmail.com");
                props.put("mail.smtp.port", "587");
                props.put("mail.smtp.auth", "true");
                props.put("mail.smtp.starttls.enable", "true");

                Session session = Session.getInstance(props, new Authenticator() {
                        protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication("jmrubinusltd@gmail.com", "udnafhivdjqzelez");
                        }
                });

                try {
                        Message message = new MimeMessage(session);
                        message.setFrom(new InternetAddress(email, "Rubi Logistics"));
                        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(email));
                        message.setSubject(subject);
                        message.setContent(body, "text/html");



                        Transport.send(message);

                } catch (MessagingException e) {
                        throw new RuntimeException(e);
                } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException(e);
                }
        }


        @PostMapping("/mobile/signup")
        public ResponseEntity<?> registerMobileUser(@Valid @RequestBody MobileSignupRequest signUpRequest) {
                if (mobileUserRepository.existsByUsername(signUpRequest.getUsername())) {
                        return ResponseEntity
                                .badRequest()
                                .body(new MessageResponse("This Username is already taken!"));
                }

                if (mobileUserRepository.existsByEmail(signUpRequest.getEmail())) {
                        return ResponseEntity
                                .badRequest()
                                .body(new MessageResponse("This Email is already in use!"));
                }
                if (mobileUserRepository.existsByPhone(signUpRequest.getPhone())) {
                        return ResponseEntity
                                .badRequest()
                                .body(new MessageResponse("This Number is already in use"));
                }

                String otp = generateOtp();
                sendOtpToEmail(signUpRequest.getEmail(), otp, signUpRequest.getName());

                MobileUser user = new MobileUser(signUpRequest.getName(),
                        signUpRequest.getUsername(),
                        signUpRequest.getEmail(),
                        encoder.encode(signUpRequest.getPassword()),
                        signUpRequest.getPhone(), otp, Status.APPROVED );
                mobileUserRepository.save(user);
                user.setOtp(otp);

                return ResponseEntity.ok(new MessageResponse(
                        "OTP has been sent to your email. Please enter the OTP to verify your account."));
        }
        @PostMapping("/verify")
        public ResponseEntity<?> verifyOtp(@Valid @RequestBody VerifyOtpRequest verifyOtpRequest) {
                String email = verifyOtpRequest.getEmail();
                String otp = verifyOtpRequest.getOtp();
                MobileUser user = mobileUserRepository.findByEmail(email).orElseThrow(
                        () -> new ResourceNotFoundException("User not found with email: " +
                                email));
                if (!otp.equals(user.getOtp())) {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new MessageResponse("Invalid OTP"));
                }
                user.setOtp(null);
                mobileUserRepository.save(user);

                return ResponseEntity.ok(new MessageResponse("OTP verified successfully"));
        }



        private String generateOtp() {
                Random random = new Random();
                int otp = 100000 + random.nextInt(900000);
                return Integer.toString(otp);
        }

        private void sendOtpToEmail(String email, String otp, String name) {

                String subject = "Verify your Rubi Logistics account - " + name;


                String htmlContent = "<html>" +
                        "<head>" +
                        "<style>" +
                        "body { font-family: Arial, sans-serif; }" +
                        ".container { max-width: 600px; margin: 0 auto; padding: 20px; }" +
                        "h1 { color: black; }" +
                        "p { margin-bottom: 20px; }" +
                        ".logo { display: block; margin-bottom: 20px; height: 40; width: 40; }" +
                        "</style>" +
                        "</head>" +
                        "<body>" +
                        "<div class=\"container\">" +
                        "<img src=\"https://i.ibb.co/0GX70CY/Photo-from-Gray.jpg\" alt=\"Rubi Logistics Logo\" class=\"logo\">" +
                        "<h1>Welcome to Rubi Logistics, " + name + "!</h1>" +
                        "<p>Your OTP to verify your Rubi Logistics account is: " + otp + "</p>" +
                        "<p>We look forward to having you on board on our platform. Kindly ignore if you did not signup with this account</p>" +
                        "<p>Cheers,</p>" +
                        "<p>The Rubi Logistics Team</p>" +
                        "</div>" +
                        "</body>" +
                        "</html>";

                Properties props = new Properties();
                props.put("mail.smtp.host", "smtp.gmail.com");
                props.put("mail.smtp.port", "587");
                props.put("mail.smtp.auth", "true");
                props.put("mail.smtp.starttls.enable", "true");

                Session session = Session.getInstance(props, new Authenticator() {
                        protected PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication("jmrubinusltd@gmail.com",
                                        "udnafhivdjqzelez");
                        }
                });

                try {
                        Message message = new MimeMessage(session);
                        message.setFrom(new InternetAddress(email, "Rubi Logistics"));
                        message.setRecipients(Message.RecipientType.TO,
                                InternetAddress.parse(email));
                        message.setSubject(subject);
                        message.setContent(htmlContent, "text/html");

                        // Transport
                        Transport.send(message);

                } catch (MessagingException e) {
                        throw new RuntimeException(e);
                } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException(e);
                }
        }
}
