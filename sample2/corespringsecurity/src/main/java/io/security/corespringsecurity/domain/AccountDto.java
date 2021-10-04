package io.security.corespringsecurity.domain;

import lombok.Data;
import org.modelmapper.ModelMapper;

@Data
public class AccountDto {

    private String userName;
    private String password;
    private String email;
    private String age;
    private String role;

    public Account toEntity() {
        ModelMapper modelMapper = new ModelMapper();
        return modelMapper.map(this, Account.class);
    }
}
