package com.sj.pgsecuritysession.repository

import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table

@Entity
@Table(name = "users")
class UserEntity(
    username: String,
    password: String,
    role: String
) {

    @Id
    val userId: Long? = null

    val username: String = username

    val password: String = password

    val role: String = role

}