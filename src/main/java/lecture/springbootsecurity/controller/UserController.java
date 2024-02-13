package lecture.springbootsecurity.controller;


import jakarta.servlet.http.HttpSession;
import lecture.springbootsecurity.dto.UserDTO;
import lecture.springbootsecurity.entity.UserEntity;
import lecture.springbootsecurity.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Slf4j // 로그관련 메소드를 편리하게 사용할 수 있음.
public class UserController {
    @Autowired
    UserService userService;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("")
    public String getAuth() {
        return "GET /auth";
    }
    
    @PostMapping("/signup")
    // ? : 와일드 카드 (어떤 값을 body에 담을 지 모름..)
    public ResponseEntity<?> registerUser(@RequestBody UserDTO userDTO) {
        try {
            UserEntity user = UserEntity.builder()
                    .email(userDTO.getEmail())
                    .username(userDTO.getUsername())
                    .password(bCryptPasswordEncoder.encode(userDTO.getPassword()))
                    .build();

            UserEntity responseUser = userService.create(user);

            UserDTO responseUserDTO = UserDTO.builder()
                    .email(responseUser.getEmail())
                    .username(responseUser.getUsername())
                    .id(responseUser.getId())
                    .build();
            return ResponseEntity.ok().body(responseUserDTO);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<?> loginUser(HttpSession session, @RequestBody UserDTO userDTO) {
        try {
            UserEntity user = userService.login(userDTO.getEmail(), userDTO.getPassword());

            if(user == null) {
                throw new RuntimeException("login failed");
            }

            UserDTO responseUserDTO = UserDTO.builder()
                    .email(user.getEmail())
                    .username(user.getUsername())
                    .id(user.getId())
                    .build();

            // log.info()
            // log.error()
             log.warn("session id {}", session.getId());
            session.setAttribute("userId", user.getId());
            return ResponseEntity.ok().body(responseUserDTO);
        } catch (Exception e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
