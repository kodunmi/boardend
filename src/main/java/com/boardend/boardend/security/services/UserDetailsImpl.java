package com.boardend.boardend.security.services;

import java.util.Collection;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.boardend.boardend.models.User;
import com.fasterxml.jackson.annotation.JsonIgnore;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;

    private Long id;

    private String companyName;

    private String email;

    private String username;

    @JsonIgnore
    private String password;

    private String streetAddress;

    private String companyState;

    private String riderNumber;

    private String accountNumber;

    private String bankName;

    private String cacNumber;

    private Collection<? extends GrantedAuthority> authorities;

    private User user; // Add this field to store the associated User object

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
