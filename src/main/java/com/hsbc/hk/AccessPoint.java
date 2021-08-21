package com.hsbc.hk;


import com.hsbc.hk.simpleauth.InMemoryAuthenticationService;
import jdk.jshell.spi.ExecutionControl;

public class AccessPoint {
    public AuthenticationService createInstance() throws ExecutionControl.NotImplementedException {
        // @TODO implement this method to return a concrete instance of @see AuthenticationService interface implementation
        return new InMemoryAuthenticationService();
    }
}
