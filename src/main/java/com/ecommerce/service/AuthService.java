package com.ecommerce.service;

import com.ecommerce.model.User;
import com.ecommerce.repository.UserRepository;
import com.ecommerce.security.JwtUtil;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    public String registerUser(User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return "User already exists!";
        }
        user.setPassword(passwordEncoder.encode(user.getPassword())); // Encrypt password
        user.setRole("USER");
        userRepository.save(user);
        return "User Registered Successfully";
    }
    public String loginUser(String username, String password) {
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isPresent()) {
            User user = userOptional.get();

            // 🔹 Debugging logs
            System.out.println("Stored Hashed Password: " + user.getPassword());
            System.out.println("Entered Password: " + password);

            if (passwordEncoder.matches(password, user.getPassword())) {
                System.out.println(" Login Successful");
                return jwtUtil.generateToken(username);  //  Return JWT token
            } else {
                System.out.println(" Password Mismatch");
                return "Invalid Credentials";
            }
        } else {
            System.out.println(" User Not Found");
        }

        return "Invalid Credentials";
    }

}
