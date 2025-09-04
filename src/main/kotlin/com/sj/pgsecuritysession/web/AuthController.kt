package com.sj.pgsecuritysession.web

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.web.bind.annotation.*

@RestController
class AuthController(
    private val authenticationManager: AuthenticationManager
) {
    data class LoginRequest(val username: String, val password: String)
    data class LoginResponse(val username: String)

    @PostMapping("/login")
    fun login(
        @RequestBody body: LoginRequest,
        request: HttpServletRequest,
        response: HttpServletResponse
    ): ResponseEntity<LoginResponse> {
        val authToken = UsernamePasswordAuthenticationToken(body.username, body.password)
        val authentication: Authentication = authenticationManager.authenticate(authToken)

        // 우선 세션을 생성(없으면)하여 쿠키 발급이 가능하도록 함
        request.getSession(true)
        // 세션 고정 공격 방지를 위해 인증 직후 세션 ID 회전
        request.changeSessionId()
        // 보안 컨텍스트 갱신 및 세션 저장
        val context = SecurityContextHolder.createEmptyContext()
        context.authentication = authentication
        SecurityContextHolder.setContext(context)
        HttpSessionSecurityContextRepository().saveContext(context, request, response)

        return ResponseEntity.ok(LoginResponse(authentication.name))
    }

    // 세션 기반 인증이 유지되는지 확인용
    @GetMapping("/me")
    fun me(@AuthenticationPrincipal user: UserDetails?): Map<String, Any?> =
        mapOf(
            "authenticated" to (user != null),
            "username" to user?.username
        )
}

