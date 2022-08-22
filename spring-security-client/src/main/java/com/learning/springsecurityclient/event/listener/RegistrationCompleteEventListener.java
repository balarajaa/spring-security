package com.learning.springsecurityclient.event.listener;

import com.learning.springsecurityclient.entity.User;
import com.learning.springsecurityclient.event.RegistrationCompleteEvent;
import com.learning.springsecurityclient.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
public class RegistrationCompleteEventListener implements ApplicationListener<RegistrationCompleteEvent> {

    @Autowired
    private UserService userService;

    @Override
    public void onApplicationEvent(RegistrationCompleteEvent event) {
        // Create the Verification Token for the user with Link
        User user = event.getUser();
        String token = UUID.randomUUID().toString();
        userService.saveVerificationTokenForUser(token,user);
        // Send mail to User
        String url = event.getApplicationUrl()
                + "/verifyRegistration?token="
                + token;

        //sendVerificationEmail
        log.info("Click the link to verify your account: {}"+url);

    }
}
