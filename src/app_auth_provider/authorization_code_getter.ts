import { LocationLike, StringMap } from '@openid/appauth/src/types';
import { QueryStringUtils } from '@openid/appauth/src/query_string_utils';

export class AuthorizationCodeGetter implements QueryStringUtils {
    parse(input: LocationLike) {
        return this.parseQueryString(input.search);
    }

    // eslint-disable-next-line class-methods-use-this
    parseQueryString(query: string): StringMap {
        const result: StringMap = {};
        const q = query.trim().replace(/^(\?|#|&)/, '');
        const params = q.split('&');
        for (let i = 0; i < params.length; i += 1) {
            const param = params[i];
            const parts = param.split('=');
            if (parts.length >= 2) {
                const key = decodeURIComponent(parts.shift()!);
                const value = parts.length > 0 ? parts.join('=') : null;
                if (value) {
                    result[key] = decodeURIComponent(value);
                }
            }
        }
        return result;
    }

    // eslint-disable-next-line class-methods-use-this
    stringify(input: StringMap) {
        const encoded: string[] = [];
        // eslint-disable-next-line no-restricted-syntax
        for (const key in input) {
            // eslint-disable-next-line no-prototype-builtins
            if (input.hasOwnProperty(key) && input[key]) {
                encoded.push(`${encodeURIComponent(key)}=${encodeURIComponent(input[key])}`);
            }
        }
        return encoded.join('&');
    }
}

export default AuthorizationCodeGetter;
