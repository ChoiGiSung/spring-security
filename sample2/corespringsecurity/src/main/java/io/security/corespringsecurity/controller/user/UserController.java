package io.security.corespringsecurity.controller.user;


import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;

	@GetMapping("/users")
	public String create(){
		return "/user/login/register";
	}

	@PostMapping("/users")
	public String create(AccountDto accountDto){
		Account account = accountDto.toEntity();
		userService.createUser(account);
		return "redirect:/";
	}

	@GetMapping(value="/mypage")
	public String myPage() throws Exception {


		return "user/mypage";
	}
}
