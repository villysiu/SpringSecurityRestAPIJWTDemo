package com.villysiu.springsecurityrestapi.repository;

import com.villysiu.springsecurityrestapi.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
}
