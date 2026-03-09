package com.example.vulnerable

import org.springframework.web.bind.annotation.*
import org.springframework.beans.factory.annotation.Value

@RestController
@RequestMapping("/api")
class UserController {

    // VULN: SpEL injection in @Value
    @Value("#{systemProperties['user.home']}")
    lateinit var userHome: String

    // VULN: Mass assignment via @RequestBody
    @PostMapping("/users")
    fun createUser(@RequestBody user: UserDto): UserDto {
        return userService.create(user)
    }

    // VULN: XSS in ResponseBody
    @GetMapping("/greet")
    @ResponseBody
    fun greet(@RequestParam name: String): String {
        return "<h1>Hello, $name!</h1>"
    }

    private val userService = UserService()
}

data class UserDto(
    val name: String,
    val email: String,
    val role: String,     // Mass assignment target
    val isAdmin: Boolean  // Mass assignment target
)

class UserService {
    fun create(user: UserDto): UserDto = user
}
