package com.boardend.boardend.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private String refreshToken;
    private Long id;
    private String name;
    private String email;
    private String username;
    private String phone;
    private String streetAddress;
    private String companyName;
    private String companyState;
    private String riderNumber;

    private String vehicleNumber;
    private String status;

    private String accountNumber;

    private String bankName;

    private String cacNumber;
    private List<String> roles;

}
