import { AuthorizationServiceConfiguration } from '@openid/appauth';
import { Reyah } from '@reyah/api-sdk';

export class Configuration {
    static getConfiguration(): AuthorizationServiceConfiguration {
        const AUTH_URL = `${Reyah.Config.getConfig().auth_protocol}://${Reyah.Config.getConfig().auth_hostname}`;
        return new AuthorizationServiceConfiguration({
            authorization_endpoint: `${AUTH_URL}/oauth2/auth`,
            token_endpoint: `${AUTH_URL}/oauth2/token`,
            revocation_endpoint: `${AUTH_URL}/oauth2/revoke`,
        });
    }
}

export default Configuration;
