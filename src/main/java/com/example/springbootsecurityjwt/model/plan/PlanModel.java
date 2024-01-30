package com.example.springbootsecurityjwt.model.plan;

import com.example.springbootsecurityjwt.model.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "plan")
@Entity
public class PlanModel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    @Column(name = "start_time")
    @JsonProperty("start_time")
    private Date startTime;

    @Column(name = "expire_time")
    @JsonProperty("expire_time")
    private Date expireTime;

    private String price;

    @Column(name = "number_of_requests")
    @JsonProperty("number_of_requests")
    private Integer numberRequest;

}
