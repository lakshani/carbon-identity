package org.wso2.carbon.identity.application.authentication.framework.exception;

public class AuthorizationFailedException extends FrameworkException {

    private static final long serialVersionUID = -7390290583990926490L;

    public AuthorizationFailedException() {
        super();
    }

    public AuthorizationFailedException(String message) {
        super(message);
    }

    public AuthorizationFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
