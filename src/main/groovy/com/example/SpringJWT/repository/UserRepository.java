package com.example.SpringJWT.repository;

import com.example.SpringJWT.Entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {
        Boolean existsByUsername(String username);
}
