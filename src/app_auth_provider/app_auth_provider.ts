import {
    AuthProvider,
    Context,
    AuthenticationException,
    NotAuthenticatedException,
    CannotRefreshSessionException,
    ReyahRequest,
    ReyahRequestError,
} from '@reyah/api-sdk';

import {
    FetchRequestor,
    RedirectRequestHandler,
    TokenResponse,
    AuthorizationResponse,
    RevokeTokenRequest,
} from '@openid/appauth';
import { NodeCrypto } from '@openid/appauth/built/node_support/';
import { NodeBasedHandler } from '@openid/appauth/built/node_support/node_request_handler';
import { NodeRequestor } from '@openid/appauth/built/node_support/node_requestor';
import { AuthorizationRequest } from '@openid/appauth/built/authorization_request';
import {
    AuthorizationRequestHandler,
    AuthorizationNotifier,
} from '@openid/appauth/built/authorization_request_handler';
import {
    GRANT_TYPE_AUTHORIZATION_CODE,
    GRANT_TYPE_REFRESH_TOKEN,
    TokenRequest,
} from '@openid/appauth/built/token_request';
import {
    BaseTokenRequestHandler,
    TokenRequestHandler,
} from '@openid/appauth/built/token_request_handler';
import querystring from 'qs';
import { Configuration } from './configuration';
import {
    Helper, BROWSER, NODE, StringMap,
} from './helper';
import { AuthorizationCodeGetter } from './authorization_code_getter';
import { AuthStateEmitter, InternalEmitter } from './emitter';
import { LocalStorage } from './storage';
import {
    AuthorizationException,
    ExchangeTokenException,
    NoPendingAuthorizationException, RefreshTokenException, RevokeException,
    UnsupportedEnvironmentException,
} from './error';

export const ACCESS_TYPE_ONLINE = 'ONLINE';
export const ACCESS_TYPE_OFFLINE = 'OFFLINE';
const STORAGE_TOKEN_KEY = 'reyah_oauth_token';
const STORAGE_AUTHORIZATION_REQUEST_HANDLE_KEY = 'appauth_current_authorization_request';

interface MakeAuthorizeParam {
    access_type?: 'ONLINE' | 'OFFLINE'
    scope?: string[] | string
}

interface AuthorizationError {
    error: string
    error_description: string
    error_hint?: string
}

export class AppAuthProvider implements AuthProvider {
    private readonly clientId: string;
    private readonly redirectUri: string;
    private storage: Storage;
    private token: TokenResponse | undefined;
    private refreshInProgress: boolean;
    private tokenExpireTimeout: number | NodeJS.Timeout;

    private authorizationHandler: AuthorizationRequestHandler;
    private tokenHandler: TokenRequestHandler;
    private readonly authStateEmitter: AuthStateEmitter;
    private readonly internalEmitter: InternalEmitter;
    private readonly notifier: AuthorizationNotifier;

    constructor(clientId: string, redirectUri: string, storage: Storage = new LocalStorage()) {
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.storage = storage;
        this.tokenExpireTimeout = 0;

        this.refreshInProgress = false;
        this.token = this.initializeToken();
        this.updateExpiredTokenEmitter();
        this.notifier = new AuthorizationNotifier();
        this.authStateEmitter = new AuthStateEmitter();
        this.internalEmitter = new InternalEmitter();
        if (Helper.getRunningEnv() === BROWSER) {
            this.authorizationHandler = new RedirectRequestHandler(undefined, new AuthorizationCodeGetter());
            this.tokenHandler = new BaseTokenRequestHandler(new FetchRequestor());
        } else {
            this.authorizationHandler = new NodeBasedHandler();
            this.tokenHandler = new BaseTokenRequestHandler(new NodeRequestor());
        }
        this.authorizationHandler.setAuthorizationNotifier(this.notifier);
        this.notifier.setAuthorizationListener((req, resp) => this.authorizationListener(req, resp));
    }

    private initializeToken(): TokenResponse | undefined {
        const token = this.storage.getItem(STORAGE_TOKEN_KEY);
        if (token === null) {
            return undefined;
        }
        try {
            return new TokenResponse(JSON.parse(token));
        } catch (e) {
            return undefined;
        }
    }

    private updateExpiredTokenEmitter(): void {
        clearTimeout(this.tokenExpireTimeout as number);
        if (this.token && !this.token.refreshToken) {
            const expireDate = new Date((this.token.issuedAt + (this.token.expiresIn || 0)) * 1000);
            if (expireDate.getTime() - Date.now() > 0) {
                this.tokenExpireTimeout = setTimeout(() => {
                    this.authStateEmitter.emit(AuthStateEmitter.ON_AUTH_STATE_CHANGED, false);
                }, expireDate.getTime() - Date.now());
            }
        }
    }

    public hasPendingAuthorizationResponse(): boolean {
        if (Helper.getRunningEnv() === NODE) {
            throw new UnsupportedEnvironmentException();
        }
        const queryParam = querystring.parse(window.location.search.substr(1));
        return (typeof queryParam.code !== 'undefined' || typeof queryParam.error !== 'undefined');
    }

    private extractAuthorizationError(): boolean {
        if (Helper.getRunningEnv() === NODE) {
            throw new UnsupportedEnvironmentException();
        }
        const queryParam = querystring.parse(window.location.search.substr(1));
        if (typeof queryParam.error === 'undefined') {
            return false;
        }
        throw new AuthorizationException(queryParam.error.toString(), queryParam.error_description?.toString() || '', queryParam.error_hint?.toString() || '');
    }

    public makeAuthorizeRequest(params?: MakeAuthorizeParam): void {
        let scope: string[] = [];
        if (params && params.access_type === ACCESS_TYPE_OFFLINE) {
            scope.push('offline');
        }
        if (params && typeof params.scope === 'string') {
            scope = [...scope, params.scope];
        } else if (params && typeof params.scope === 'object') {
            scope = [...scope, ...params.scope];
        }
        const request = new AuthorizationRequest({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            scope: scope.join(' '),
            response_type: AuthorizationRequest.RESPONSE_TYPE_CODE,
        }, (Helper.getRunningEnv() === NODE) ? new NodeCrypto() : undefined, true);
        this.authorizationHandler.performAuthorizationRequest(Configuration.getConfiguration(), request);
    }

    public completeAuthorizationRequestIfPossible(): Promise<AuthorizationError | undefined> {
        return new Promise((resolve, reject) => {
            if (Helper.getRunningEnv() === BROWSER) {
                if (!this.hasPendingAuthorizationResponse()) {
                    return reject(new NoPendingAuthorizationException());
                }
                this.extractAuthorizationError();
                if (this.storage.getItem(STORAGE_AUTHORIZATION_REQUEST_HANDLE_KEY) === null) {
                    return reject(new NoPendingAuthorizationException());
                }
            }
            return this.authorizationHandler.completeAuthorizationRequestIfPossible().then(() => resolve());
        });
    }

    private makeTokenExchange(code: string, codeVerifier: string | undefined): Promise<void> {
        const extras: StringMap = {};

        if (codeVerifier) {
            extras.code_verifier = codeVerifier;
        }
        const request = new TokenRequest({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
            code,
            extras,
        });
        return this.tokenHandler.performTokenRequest(Configuration.getConfiguration(), request)
            .then((resp) => {
                this.token = resp;
                this.storage.setItem(STORAGE_TOKEN_KEY, JSON.stringify(this.token.toJson()));
                this.updateExpiredTokenEmitter();
            })
            .then(() => {
            }).catch((err) => {
                throw new ExchangeTokenException(err);
            });
    }

    private authorizationListener(request: AuthorizationRequest, response: AuthorizationResponse | null): void {
        if (response) {
            let codeVerifier: string | undefined;
            if (request.internal && request.internal.code_verifier) {
                codeVerifier = request.internal.code_verifier;
            }
            this.makeTokenExchange(response.code, codeVerifier)
                .then(() => {
                    this.authStateEmitter.emit(AuthStateEmitter.ON_AUTH_STATE_CHANGED, true);
                })
                .catch((err) => this.authStateEmitter.emit(AuthStateEmitter.ON_ERROR, err));
        }
    }

    public getAuthStateEmitter(): AuthStateEmitter {
        return this.authStateEmitter;
    }

    public revoke(): Promise<boolean> {
        if (!this.token) {
            return Promise.resolve(true);
        }
        let request: RevokeTokenRequest;
        if (this.token.refreshToken) {
            request = new RevokeTokenRequest({
                token: this.token.refreshToken,
                token_type_hint: 'refresh_token',
                client_id: this.clientId,
            });
        } else {
            request = new RevokeTokenRequest({
                token: this.token.accessToken,
                token_type_hint: 'access_token',
                client_id: this.clientId,
            });
        }
        return this.tokenHandler.performRevokeTokenRequest(Configuration.getConfiguration(), request)
            .then((success) => {
                if (success) {
                    this.token = undefined;
                    this.storage.removeItem(STORAGE_TOKEN_KEY);
                    this.authStateEmitter.emit(AuthStateEmitter.ON_AUTH_STATE_CHANGED, false);
                }
                return success;
            })
            .catch((err) => {
                throw new RevokeException(err);
            });
    }

    public getName(): string {
        return AppAuthProvider.name;
    }

    private getFreshToken(): Promise<TokenResponse> {
        if (!this.token) {
            return Promise.reject(new NotAuthenticatedException());
        }
        if (!this.token.refreshToken && this.token.isValid(0)) {
            return Promise.resolve(this.token);
        }
        if (!!this.token.refreshToken && this.token.isValid()) {
            return Promise.resolve(this.token);
        }
        return this.refreshToken();
    }

    private onTokenRefreshed(resolve: (t: TokenResponse) => void, reject: (e: any) => void, timeoutRef: number | NodeJS.Timeout): (succeeded: boolean, token: TokenResponse | any) => void {
        return (succeeded: boolean, resp: TokenResponse | any) => {
            clearTimeout(timeoutRef as number);
            if (succeeded) {
                resolve(resp);
            } else {
                reject(resp);
            }
        };
    }

    private waitRefreshToken(): Promise<TokenResponse> {
        return new Promise((resolve, reject) => {
            const timeoutRef = setTimeout(() => {
                reject(new AuthenticationException('Timeout while waiting new token'));
            }, 10000);
            this.internalEmitter.once(InternalEmitter.ON_TOKEN_REFRESHED, this.onTokenRefreshed(resolve, reject, timeoutRef));
        });
    }

    private executeRefreshToken(): Promise<TokenResponse> {
        return new Promise((resolve, reject) => {
            if (!this.token) {
                reject(new NotAuthenticatedException());
                return;
            }
            const request = new TokenRequest({
                client_id: this.clientId,
                redirect_uri: this.redirectUri,
                grant_type: GRANT_TYPE_REFRESH_TOKEN,
                refresh_token: this.token.refreshToken,
            });
            this.tokenHandler
                .performTokenRequest(Configuration.getConfiguration(), request)
                .then((response) => {
                    this.token = response;
                    this.refreshInProgress = false;
                    this.storage.setItem(STORAGE_TOKEN_KEY, JSON.stringify(this.token.toJson()));
                    this.internalEmitter.emit(InternalEmitter.ON_TOKEN_REFRESHED, true, this.token);
                    resolve(this.token);
                })
                .catch((err) => {
                    const exception = new RefreshTokenException(err);
                    this.refreshInProgress = false;
                    this.internalEmitter.emit(InternalEmitter.ON_TOKEN_REFRESHED, false, exception);
                    reject(exception);
                });
        });
    }

    private refreshToken(): Promise<TokenResponse> {
        if (!this.token) {
            return Promise.reject(new NotAuthenticatedException());
        }
        if (!this.token.refreshToken) {
            return Promise.reject(new CannotRefreshSessionException());
        }
        if (this.refreshInProgress) {
            return this.waitRefreshToken();
        }
        this.refreshInProgress = true;
        return this.executeRefreshToken();
    }

    public getTokenExpiry(): Date {
        if (!this.token) {
            throw new NotAuthenticatedException();
        }
        return new Date((this.token.issuedAt + (this.token.expiresIn || 0)) * 1000);
    }

    public canBeRenewed(): boolean {
        if (!this.token) {
            throw new NotAuthenticatedException();
        }
        return !!this.token.refreshToken;
    }

    public async applyAuth(request: ReyahRequest, ctx: Context): Promise<void> {
        if (!this.isLoggedIn()) {
            throw new NotAuthenticatedException();
        }
        let token: TokenResponse;
        if (ctx.lastError !== undefined && ctx.lastError instanceof ReyahRequestError && ctx.lastError.isReyahRequestError && ctx.lastError.code === 401) {
            token = await this.refreshToken();
        } else {
            token = await this.getFreshToken();
        }
        request.setHeader('Authorization', `${token.tokenType} ${token.accessToken}`);
    }

    public isLoggedIn(): boolean {
        if (!this.token) {
            return false;
        }
        if (!this.token.refreshToken) {
            return this.token.isValid(0);
        }
        return !!(this.token.isValid() || this.token.refreshToken);
    }
}
