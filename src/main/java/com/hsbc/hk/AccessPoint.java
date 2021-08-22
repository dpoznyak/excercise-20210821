package com.hsbc.hk;


import com.hsbc.hk.simpleauth.InMemoryAuthenticationService;
import jdk.jshell.spi.ExecutionControl;

import java.time.Duration;

public class AccessPoint {
    public AuthenticationService createInstance() throws ExecutionControl.NotImplementedException {
        // @TODO: service parameters must be injected via appropriate mechanism from configs/secrets.
        return new InMemoryAuthenticationService("Key213124134", Duration.ofDays(1));
    }
}
