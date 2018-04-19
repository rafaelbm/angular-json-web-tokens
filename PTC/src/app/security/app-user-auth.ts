import { AppUserClaim } from './app-user-claim';

export class AppUserAuth {
    username = '';
    bearerToken = '';
    isAuthenticated = false;
    claims: AppUserClaim[] = [];
}
