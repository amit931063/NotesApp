package com.NotesApp.NotesApp.controllers;
import com.NotesApp.NotesApp.models.ERole;
import com.NotesApp.NotesApp.models.Role;
import com.NotesApp.NotesApp.models.User;
import com.NotesApp.NotesApp.payloads.LoginRequest;
import com.NotesApp.NotesApp.payloads.request.SignUpRequest;
import com.NotesApp.NotesApp.payloads.request.TokenRefreshRequest;
import com.NotesApp.NotesApp.payloads.response.JwtResponse;
import com.NotesApp.NotesApp.payloads.response.MessageResponse;
import com.NotesApp.NotesApp.repositories.RoleRepository;
import com.NotesApp.NotesApp.repositories.UserRepository;
import com.NotesApp.NotesApp.security.jwt.JwtUtils;
import com.NotesApp.NotesApp.services.PasswordResetService;
import com.NotesApp.NotesApp.services.RefreshTokenService;
import com.NotesApp.NotesApp.services.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
//
//    @Autowired
//    AuthenticationManager authenticationManager;
//
//    @Autowired
//    UserRepository userRepository;
//
//    @Autowired
//    RoleRepository roleRepository;
//
//    @Autowired
//    PasswordEncoder passwordEncoder;
//
//    @Autowired
//    RefreshTokenService refreshTokenService;
//    @Autowired
//    JwtUtils jwtUtils;
//
//    // Define your authentication endpoints here, e.g., login, register, etc.
//
////    @PostMapping("/signin")
////    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
////        // Implement authentication logic here
////        Authentication authentication = authenticationManager.authenticate(
////                new UsernamePasswordAuthenticationToken(
////                        loginRequest.getUsername(),
////                        loginRequest.getPassword()
////                )
////        );
////
////        SecurityContextHolder.getContext().setAuthentication(authentication);
////        // If authentication is successful, you can generate a JWT token
////        String jwt = jwtUtils.generateJwtToken(authentication);
////        // Get the authenticated user's details
////        UserDetailsImpl userDetailsImp = (UserDetailsImpl) authentication.getPrincipal();
////        // Extract roles from UserDetailsImp and convert them to a List<String>
////        List<String> roles = userDetailsImp.getAuthorities().stream()
////                .map(authority -> authority.getAuthority())
////                .collect(Collectors.toList());
////
////        // You can also return additional user details if needed
////        return ResponseEntity.ok(new JwtResponse(jwt, ,
////                userDetailsImp.getId(),
////                userDetailsImp.getUsername(),
////                userDetailsImp.getEmail(),
////                roles));
////    }
//
////    @PostMapping("/signin")
////    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
////        // Authenticate user
////        Authentication authentication = authenticationManager.authenticate(
////                new UsernamePasswordAuthenticationToken(
////                        loginRequest.getUsername(),
////                        loginRequest.getPassword()
////                )
////        );
////
////        SecurityContextHolder.getContext().setAuthentication(authentication);
////
////        // Generate JWT access token
////        String jwt = jwtUtils.generateJwtToken(authentication);
////
////        // Get user details
////        UserDetailsImpl userDetailsImp = (UserDetailsImpl) authentication.getPrincipal();
////
////        // Generate refresh token (you can use the same method or a new one)
////        String refreshToken = jwtUtils.generateRefreshToken(userDetailsImp.getUsername());
////
////        // Extract roles
////        List<String> roles = userDetailsImp.getAuthorities().stream()
////                .map(authority -> authority.getAuthority())
////                .collect(Collectors.toList());
////
////        // Build and return JWT + Refresh response
////        return ResponseEntity.ok(new JwtResponse(
////                jwt,
////                refreshToken,
////                userDetailsImp.getId(),
////                userDetailsImp.getUsername(),
////                userDetailsImp.getEmail(),
////                roles
////        ));
////    }
//
//    // code of 23/07/25 //
//
//
//    @PostMapping("/signin")
//    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
//        String loginInput = loginRequest.getUsername(); // this may be username or email
//        String password = loginRequest.getPassword();
//
//        //  Find user by username or email
//        Optional<User> userOptional = userRepository.findByUsername(loginInput);
//        if (userOptional.isEmpty()) {
//            userOptional = userRepository.findByEmail(loginInput);
//        }
//
//        if (userOptional.isEmpty()) {
//            return ResponseEntity
//                    .status(HttpStatus.UNAUTHORIZED)
//                    .body(new MessageResponse("Invalid username/email or password"));
//        }
//
//        User user = userOptional.get();
//
//        //  Authenticate using correct username (not email)
//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        user.getUsername(), // always use actual username here
//                        password
//                )
//        );
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        //  Generate JWT access token
//        String jwt = jwtUtils.generateJwtToken(authentication);
//
//        //  Get UserDetailsImpl for response data
//        UserDetailsImpl userDetailsImp = (UserDetailsImpl) authentication.getPrincipal();
//
//        //  Generate refresh token (optional: from DB or JWT utils)
//        String refreshToken = jwtUtils.generateRefreshToken(userDetailsImp.getUsername());
//
//        //  Get roles
//        List<String> roles = userDetailsImp.getAuthorities().stream()
//                .map(authority -> authority.getAuthority())
//                .collect(Collectors.toList());
//
//        //  Return response
//        return ResponseEntity.ok(new JwtResponse(
//                jwt,
//                refreshToken,
//                userDetailsImp.getId(),
//                userDetailsImp.getUsername(),
//                userDetailsImp.getEmail(),
//                roles
//        ));
//    }
//
//
//    //   code of 23/07/25 //
//
////    @PostMapping("/signup")
////    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest request){
////        if (userRepository.existsByUsername(request.getUsername()))
////            return ResponseEntity
////                    .badRequest()
////                    .body(new MessageResponse("Error: Username is already taken!"));
////
////        if (userRepository.existsByEmail(request.getEmail()))
////            return ResponseEntity
////                    .badRequest()
////                    .body(new MessageResponse("Error: Email is already in use!"));
////
////        User user = new User(request.getUsername(),
////                request.getEmail(),
////                passwordEncoder.encode(request.getPassword()));
////
////        Set<String> strRoles = request.getRole();
////        Set<Role> roles = new HashSet<>();
////
////        if (strRoles == null || strRoles.isEmpty()){
//////            Optional<Role> userRole = roleRepository.findByName(ERole.ROLE_USER);
////            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
////                    .orElseThrow(() -> new RuntimeException("Role not found"));
////            roles.add(userRole);
////        }else {
////            strRoles.forEach(role -> {
////                switch (role){
////                    case "admin":
////                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
////                                .orElseThrow(()-> new RuntimeException("Error: Role is not found."));
////                        roles.add(adminRole);
////break;
//////                        break;
//////                    case "mod":
//////                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
//////                                .orElseThrow(()-> new RuntimeException("Error: Role is not found."));
//////                        roles.add(modRole);
//////
//////                        break;
////                    default:
////                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
////                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
////                        roles.add(userRole);
////                }
////            });
////        }
////
////        user.setRoles(roles);
////        userRepository.save(user);
////
////        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
////    }
//    //  previous code for refresh Token //
//
////    @PostMapping("/refreshtoken")
////    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
////        return refreshTokenService.findByToken(request.getRefreshToken())
////                .map(refreshTokenService::verifyExpiration)
////                .map(RefreshToken::getUser)
////                .map(user -> {
////                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
////                    return ResponseEntity.ok(new TokenRefreshResponse(token, request.getRefreshToken()));
////                })
////                .orElseThrow(() -> new RuntimeException("Refresh token not found"));
////    }
//
////@PostMapping("/refresh-token")
////public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
////    String refreshToken = request.getRefreshToken();
////
////    if (jwtUtils.validateJwtToken(refreshToken)) {
////        String username = jwtUtils.getUserNameFromJwtToken(refreshToken);
////        String newAccessToken = jwtUtils.generateJwtTokenFromUsername(username);
////
////        return ResponseEntity.ok(new JwtResponse(newAccessToken, refreshToken));
////    } else {
////        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid refresh token.");
////    }
////}
//
//    @PostMapping("/signup")
//    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
//        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
//            return ResponseEntity
//                    .badRequest()
//                    .body(new MessageResponse("Error: Username is already taken!"));
//        }
//
//        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
//            return ResponseEntity
//                    .badRequest()
//                    .body(new MessageResponse("Error: Email is already in use!"));
//        }
//
//        // Create new user's account
//        User user = new User(
//                signUpRequest.getUsername(),
//                signUpRequest.getEmail(),
//                passwordEncoder.encode(signUpRequest.getPassword())
//        );
//
//        Set<Role> roles = new HashSet<>();
//
//        // 🔐 Check if the email belongs to the company admin list
//        String email = signUpRequest.getEmail();
//        if (email.toLowerCase().endsWith("@company.com")) {
//            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
//                    .orElseThrow(() -> new RuntimeException("Error: Admin role is not found."));
//            roles.add(adminRole);
//        } else {
//            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
//                    .orElseThrow(() -> new RuntimeException("Error: User role is not found."));
//            roles.add(userRole);
//        }
//
//        user.setRoles(roles);
//        userRepository.save(user);
//
//        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
//    }
//
////    @PostMapping("/refresh-token")
////    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
////        String refreshToken = request.getRefreshToken();
////
////        if (jwtUtils.validateJwtToken(refreshToken)) {
////            String username = jwtUtils.getUserNameFromJwtToken(refreshToken);
////
////            // Load user from database
////            User user = userRepository.findByUsername(username)
////                    .orElseThrow(() -> new RuntimeException("User not found"));
////
////            // Extract roles as List<String>
////            List<String> roles = user.getRoles().stream()
////                    .map(role -> role.getName().name())
////                    .collect(Collectors.toList());
////
////            // Generate new access token
////            String newAccessToken = jwtUtils.generateJwtTokenFromUsername(username);
////
////            // Return full JwtResponse
////            return ResponseEntity.ok(new JwtResponse(
////                    newAccessToken,
////                    refreshToken,
////                    user.getId(),
////                    user.getUsername(),
////                    user.getEmail(),
////                    roles
////            ));
////        } else {
////            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid refresh token.");
////        }
////    }
//
//
//    @PostMapping("/refresh-token")
//    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
//        String refreshToken = request.getRefreshToken();
//
//        if (jwtUtils.validateJwtToken(refreshToken)) {
//            String username = jwtUtils.getUserNameFromJwtToken(refreshToken);
//
//            // Load user from DB
//            User user = userRepository.findByUsername(username)
//                    .orElseThrow(() -> new RuntimeException("User not found"));
//
//            // Extract roles as List<String>
//            List<String> roles = user.getRoles().stream()
//                    .map(role -> role.getName().name())
//                    .collect(Collectors.toList());
//
//            // Generate new access token
//            String newAccessToken = jwtUtils.generateJwtTokenFromUsername(username);
//
//            return ResponseEntity.ok(new JwtResponse(
//                    newAccessToken,
//                    refreshToken,
//                    user.getId(),
//                    user.getUsername(),
//                    user.getEmail(),
//                    roles
//            ));
//        } else {
//            return ResponseEntity.status(HttpStatus.FORBIDDEN)
//                    .body(new MessageResponse("Invalid or expired refresh token"));
//        }
//    }
//
//
//
//    //    @Autowired
////    PasswordResetTokenRepository resetTokenRepository;
////
////    @Autowired
////    EmailService emailService;
////
////    @PostMapping("/forgot-password")
////    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
////        Optional<User> userOptional = userRepository.findByEmail(email);
////        if (userOptional.isEmpty()) {
////            return ResponseEntity.badRequest().body(new MessageResponse("Email not found"));
////        }
////
////        User user = userOptional.get();
////        String token = UUID.randomUUID().toString();
////
////        PasswordResetToken resetToken = new PasswordResetToken();
////        resetToken.setToken(token);
////        resetToken.setUser(user);
////        resetToken.setExpiryDate(LocalDateTime.now().plusSeconds(900)); // 15 min
////        resetTokenRepository.save(resetToken);
////
////        String resetLink = "http://localhost:8080/reset-password?token=" + token;
////        emailService.sendEmail(email, "Reset Your Password", "Click here: " + resetLink);
////
////        return ResponseEntity.ok(new MessageResponse("Reset link sent to your email"));
////    }
////
////    @PostMapping("/reset-password")
////    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String newPassword) {
////        Optional<PasswordResetToken> tokenOptional = resetTokenRepository.findByToken(token);
////        if (tokenOptional.isEmpty()) {
////            return ResponseEntity.badRequest().body(new MessageResponse("Invalid token"));
////        }
////
////        PasswordResetToken resetToken = tokenOptional.get();
////        if (resetToken.getExpiryDate().isBefore(Instant.now())) {
////            return ResponseEntity.badRequest().body(new MessageResponse("Token expired"));
////        }
////
////        User user = resetToken.getUser();
////        user.setPassword(passwordEncoder.encode(newPassword));
////        userRepository.save(user);
////        resetTokenRepository.delete(resetToken);
////
////        return ResponseEntity.ok(new MessageResponse("Password updated successfully"));
////    }
//    @Autowired
//    private PasswordResetService resetService;
//
//    @PostMapping("/forgot-password")
//    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> body) {
//        resetService.createPasswordResetToken(body.get("email"));
//        return ResponseEntity.ok("Reset link sent to email.");
//    }
//
//    @PostMapping("/reset-password")
//    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
//        String token = body.get("token");
//        String newPassword = body.get("newPassword");
//
//        resetService.resetPassword(token, newPassword);
//        return ResponseEntity.ok("Password reset successful.");
//    }



    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    JwtUtils jwtUtils;

    // ✅ LOGIN (username or email)
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
//        String loginInput = loginRequest.getUsername(); // may be username or email
//        String password = loginRequest.getPassword();
//
//        // Find user by username or email
//        Optional<User> userOptional = userRepository.findByUsername(loginInput);
//        if (userOptional.isEmpty()) {
//            userOptional = userRepository.findByEmail(loginInput);
//        }
//
//        if (userOptional.isEmpty()) {
//            return ResponseEntity
//                    .status(HttpStatus.UNAUTHORIZED)
//                    .body(new MessageResponse("Invalid username/email or password"));
//        }
//
//        User user = userOptional.get();
//
//        // Authenticate using username
//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        user.getUsername(),
//                        password
//                )
//        );
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        // Generate JWT access token
//        String jwt = jwtUtils.generateJwtToken(authentication);
//
//        // UserDetails
//        UserDetailsImpl userDetailsImp = (UserDetailsImpl) authentication.getPrincipal();
//
//        // Refresh token
//        String refreshToken = jwtUtils.generateRefreshToken(userDetailsImp.getUsername());
//
//        // ✅ Return without roles
//        return ResponseEntity.ok(new JwtResponse(
//                jwt,
//                refreshToken,
//                userDetailsImp.getId(),
//                userDetailsImp.getUsername(),
//                userDetailsImp.getEmail()
//        ));
        String loginInput = loginRequest.getUsername(); // can be username or email
        String password = loginRequest.getPassword();

        // Try to find user by username first
        Optional<User> userOptional = userRepository.findByUsername(loginInput);

        // If not found, try by email
        if (userOptional.isEmpty()) {
            userOptional = userRepository.findByEmail(loginInput);
        }

        if (userOptional.isEmpty()) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid username/email or password"));
        }

        User user = userOptional.get();

        // Authenticate always with username (Spring Security requires a unique username)
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(), // ✅ always username
                        password
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate JWT access token
        String jwt = jwtUtils.generateJwtToken(authentication);

        // UserDetails
        UserDetailsImpl userDetailsImp = (UserDetailsImpl) authentication.getPrincipal();

        // Generate refresh token
        String refreshToken = jwtUtils.generateRefreshToken(userDetailsImp.getUsername());

        // ✅ Return response without roles
        return ResponseEntity.ok(new JwtResponse(
                jwt,
                refreshToken,
                userDetailsImp.getId(),
                userDetailsImp.getUsername(),
                userDetailsImp.getEmail()
        ));
    }

    // ✅ SIGNUP (no role assignment)
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                passwordEncoder.encode(signUpRequest.getPassword())
        );

        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    // ✅ REFRESH TOKEN
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
        String refreshToken = request.getRefreshToken();

        if (jwtUtils.validateJwtToken(refreshToken)) {
            String username = jwtUtils.getUserNameFromJwtToken(refreshToken);

            // Load user from DB
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Generate new access token
            String newAccessToken = jwtUtils.generateJwtTokenFromUsername(username);

            // ✅ Return without roles
            return ResponseEntity.ok(new JwtResponse(
                    newAccessToken,
                    refreshToken,
                    user.getId(),
                    user.getUsername(),
                    user.getEmail()
            ));
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new MessageResponse("Invalid or expired refresh token"));
        }
    }

    // ✅ FORGOT / RESET PASSWORD
    @Autowired
    private PasswordResetService resetService;

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> body) {
        resetService.createPasswordResetToken(body.get("email"));
        return ResponseEntity.ok("Reset link sent to email.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
        String token = body.get("token");
        String newPassword = body.get("newPassword");

        resetService.resetPassword(token, newPassword);
        return ResponseEntity.ok("Password reset successful.");
    }
}
