package com.villysiu.springsecurityrestapi.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

public class Account {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @NotBlank(message = "Name is required")
    private String nickname;

    @NotBlank(message = "email is required")
    @Email
    @Column(unique = true)
    private String email;

    @NotBlank(message = "Password is required")
    private String password;

    @ManyToMany(fetch = FetchType.EAGER )
    @JoinTable(name = "account_roles",
            joinColumns = @JoinColumn(name = "account_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();


    public Account(String nickname, String email, String password) {
        this.nickname = nickname;
        this.email = email;
        this.password = password;

    }

}
