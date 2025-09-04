package com.NotesApp.NotesApp.services;
import com.NotesApp.NotesApp.models.PasswordResetToken;
import com.NotesApp.NotesApp.models.User;
import com.NotesApp.NotesApp.repositories.PasswordResetTokenRepository;
import com.NotesApp.NotesApp.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@Service
public class PasswordResetService {

    @Autowired
    private PasswordResetTokenRepository tokenRepository;

    @Autowired
    private UserRepository userRepository;

        @Autowired
    EmailService emailService;

    public void createPasswordResetToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Delete old token if exists
        tokenRepository.deleteByUser(user);

        String token = UUID.randomUUID().toString();
        Date expiryDate = new Date(System.currentTimeMillis() + 15 * 60 * 1000); // 15 minutes

        PasswordResetToken resetToken = new PasswordResetToken(token, user, expiryDate);
        tokenRepository.save(resetToken);

        // Ideally send email with reset link
//        System.out.println("Reset link: http://localhost:8080/api/auth/reset-password?token=" + token);
                String resetLink = "http://localhost:8080/reset-password?token=" + token;
        emailService.sendEmail(email, "Reset Your Password", "Click here: " + resetLink);

//        return ResponseEntity.ok(new MessageResponse("Reset link sent to your email"));

    }

    public boolean resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (resetToken.getExpiryDate().before(new Date())) {
            throw new RuntimeException("Token expired");
        }

        User user = resetToken.getUser();
        user.setPassword(new BCryptPasswordEncoder().encode(newPassword));
        userRepository.save(user);

        tokenRepository.delete(resetToken);
        return true;
    }
}
