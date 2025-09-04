package com.sj.pgsecuritysession.service

import com.sj.pgsecuritysession.repository.UserRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class DbUserDetailsService(
    private val userRepository: UserRepository
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val user = userRepository.findByUsername(username)
            ?: throw UsernameNotFoundException("User not found: $username")

        val authorities = user.role
            .split(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { role -> if (role.startsWith("ROLE_")) role else "ROLE_$role" }
            .map { SimpleGrantedAuthority(it) }

        return User(user.username, user.password, authorities)
    }
}


