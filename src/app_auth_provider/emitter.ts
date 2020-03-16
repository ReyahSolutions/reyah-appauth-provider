import { EventEmitter } from 'events';

export class AuthStateEmitter extends EventEmitter {
    static ON_AUTH_STATE_CHANGED = 'on_auth_state_changed';
    static ON_ERROR = 'on_error';
}

export class InternalEmitter extends EventEmitter {
    static ON_TOKEN_REFRESHED = 'on_token_refreshed';
}
