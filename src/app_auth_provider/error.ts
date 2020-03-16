import { AuthenticationException } from '@reyah/api-sdk';

export class UnsupportedEnvironmentException extends AuthenticationException {
    name: string;

    constructor() {
        super('This functionality is not supported on this environment');
        this.name = UnsupportedEnvironmentException.name;
        Object.setPrototypeOf(this, UnsupportedEnvironmentException.prototype);
    }
}

export class OAuthException extends AuthenticationException {
    name: string;
    error: string;
    error_description: string;
    error_hint?: string;

    constructor(message?: string) {
        super(message || 'An unexpected error happened while communicating with the OAuth2.0 server');
        this.name = OAuthException.name;
        this.error = 'unknown_error';
        this.error_description = 'An unexpected error happened while communicating with OAuth2.0 server';
        Object.setPrototypeOf(this, OAuthException.prototype);
    }
}

export class AuthorizationException extends OAuthException {
    name: string;
    error: string;
    error_description: string;
    error_hint?: string;

    constructor(error: string, errorDescription: string, errorHint?: string) {
        super('An error happened during the authorization');
        this.name = AuthorizationException.name;
        this.error = error;
        this.error_description = errorDescription;
        this.error_hint = errorHint;
        Object.setPrototypeOf(this, AuthorizationException.prototype);
    }
}

export class NoPendingAuthorizationException extends AuthorizationException {
    name: string;

    constructor() {
        super('no_pending_authorization', 'There is no pending authorization');
        this.name = NoPendingAuthorizationException.name;
        Object.setPrototypeOf(this, NoPendingAuthorizationException.prototype);
    }
}

export class ExchangeTokenException extends OAuthException {
    name: string;
    error: string;
    error_description: string;
    error_hint?: string;
    originalErr: Error;

    constructor(err: Error) {
        super('Could not exchange the authorization code for an access token');
        this.name = ExchangeTokenException.name;
        this.error = 'exchange_error';
        this.error_description = 'The authorization code could not be exchanged for an access token';
        this.error_hint = 'Retry later';
        this.originalErr = err;
        Object.setPrototypeOf(this, ExchangeTokenException.prototype);
    }
}

export class RefreshTokenException extends OAuthException {
    name: string;
    originalErr: Error;

    constructor(err: Error) {
        super('Could not refresh the access token using the refresh token');
        this.name = RefreshTokenException.name;
        this.originalErr = err;
        Object.setPrototypeOf(this, RefreshTokenException.prototype);
    }
}

export class RevokeException extends OAuthException {
    name: string;
    originalErr: Error;

    constructor(err: Error) {
        super('Could not revoke the access token');
        this.name = RevokeException.name;
        this.originalErr = err;
        Object.setPrototypeOf(this, RevokeException.prototype);
    }
}
