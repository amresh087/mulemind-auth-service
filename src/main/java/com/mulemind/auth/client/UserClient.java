package com.mulemind.auth.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.mulemind.auth.dto.UserDto;

@FeignClient(name = "tenant-service", url = "${tenant.service.url}")
public interface UserClient {

    @GetMapping("/tenants/users/by-username")
    UserDto getByUsername(@RequestParam String username);
    
    
}
