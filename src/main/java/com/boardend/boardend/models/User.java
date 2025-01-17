package com.boardend.boardend.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "business_user", uniqueConstraints = {
        @UniqueConstraint(columnNames = "companyName"),
        @UniqueConstraint(columnNames = "email"),
        @UniqueConstraint(columnNames = "username") // Add unique constraint for the username field
})
@Component
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(max = 50)
    private String companyName;


    @NotBlank
    @Size(max = 50)
    @Column(unique = true)
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    @NotBlank
    @Size(max = 120)
    private String password;

    @NotBlank
    @Size(max = 200)
    private String cacNumber;

    @NotBlank
    @Size(max = 200)
    private String streetAddress;

    @NotBlank
    @Size(max = 50)
    private String companyState;

    @Size(max = 200)
    private String riderNumber;

    @Size(max = 200)
    private String accountNumber;

    @Size(max = 200)
    private String bankName;

    @Column(name = "reset_token")
    private String resetToken;

    @Enumerated(EnumType.STRING)
    private Status status;

    @Column(name = "reset_token_expiration")
    private Instant resetTokenExpiration;

    @CreationTimestamp
    @Column(name = "timestamp")
    private LocalDateTime timestamp;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "business_user_roles", joinColumns = @JoinColumn(name = "business_user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();
}
