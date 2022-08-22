package com.learning.springsecurityclient.service;

import com.learning.springsecurityclient.config.WebSecurityConfig;
import com.learning.springsecurityclient.entity.PasswordResetToken;
import com.learning.springsecurityclient.entity.User;
import com.learning.springsecurityclient.entity.VerificationToken;
import com.learning.springsecurityclient.model.UserModel;
import com.learning.springsecurityclient.repository.PasswordResetTokenRepository;
import com.learning.springsecurityclient.repository.UserRepository;
import com.learning.springsecurityclient.repository.VerificationTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User registerUser(UserModel userModel) {
        User user = new User();
        user.setEmail(userModel.getEmail());
        user.setFirstName(userModel.getFirstName());
        user.setLastName(userModel.getLastName());
        user.setRole("USER");
        user.setPassword(passwordEncoder.encode(userModel.getPassword()));
        repository.save(user);
        return user;
    }

    public void saveVerificationTokenForUser(String token, User user) {
        VerificationToken token1 = new VerificationToken(user,token);
        verificationTokenRepository.save(token1);

    }

    public String validateVerificationToken(String token) {
        VerificationToken verificationToken =
                verificationTokenRepository.findByToken(token);
        if (verificationToken == null) {
            return "invalid token";
        }
        User user = verificationToken.getUser();
        Calendar calendar = Calendar.getInstance();
        System.out.println("Expiration time : "+verificationToken.getExpirationTime().getTime());
        System.out.println("Current time : "+calendar.getTime().getTime());
        if((verificationToken.getExpirationTime().getTime() - calendar.getTime().getTime()) <=0)
        {
            verificationTokenRepository.delete(verificationToken);
            System.out.println("Token Expired.....");
            return "Token Expired";
        }
        user.setEnabled(true);
        repository.save(user);
        return "valid";
    }

    public VerificationToken generateNewVerificationToken(String oldToken) {
        VerificationToken verificationToken
                = verificationTokenRepository.findByToken(oldToken);
        verificationToken.setToken(UUID.randomUUID().toString());
        verificationTokenRepository.save(verificationToken);
        return verificationToken;
    }

    public User findUserByEmail(String email) {
        return repository.findByEmail(email);
    }

    public void createPasswordResetTokenForUser(User user, String token) {
        PasswordResetToken passwordResetToken
                = new PasswordResetToken(user,token);
        passwordResetTokenRepository.save(passwordResetToken);
    }

    public String validatePasswordResetToken(String token) {
        PasswordResetToken passwordResetToken
                = passwordResetTokenRepository.findByToken(token);

        if (passwordResetToken == null) {
            return "invalid";
        }

        User user = passwordResetToken.getUser();
        Calendar cal = Calendar.getInstance();

        if ((passwordResetToken.getExpirationTime().getTime()
                - cal.getTime().getTime()) <= 0) {
            passwordResetTokenRepository.delete(passwordResetToken);
            return "expired";
        }

        return "valid";
    }

    public Optional<User> getUserByPasswordResetToken(String token) {
        return Optional.ofNullable(passwordResetTokenRepository.findByToken(token).getUser());
    }

    public void changePassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        repository.save(user);
    }

    public boolean checkIfValidOldPassword(User user, String oldPassword) {
        return passwordEncoder.matches(oldPassword, user.getPassword());
    }
}
