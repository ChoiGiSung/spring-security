package io.security.corespringsecurity.controller;


import io.security.corespringsecurity.domain.AccountDto;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class HomeController {

	@PreAuthorize("hasRole('ROLE_USER') and #account.user == principal.username")
	@GetMapping(value="/")
	public String home(AccountDto accountDto, Principal principal) throws Exception {
		return "home";
	}

}
