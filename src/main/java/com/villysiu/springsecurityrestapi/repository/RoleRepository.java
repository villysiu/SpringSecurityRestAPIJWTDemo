package com.villysiu.springsecurityrestapi.repository;

import com.villysiu.springsecurityrestapi.model.ERole;
import com.villysiu.springsecurityrestapi.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByErole(ERole erole);
}
