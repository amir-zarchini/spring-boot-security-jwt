package com.example.springbootsecurityjwt.repository;

import com.example.springbootsecurityjwt.model.plan.Consumption;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ConsumptionRepository extends JpaRepository<Consumption, Long> {
    Consumption findByUserId(Long userId);
}
