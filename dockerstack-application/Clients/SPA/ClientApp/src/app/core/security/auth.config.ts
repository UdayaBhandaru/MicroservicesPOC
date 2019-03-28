// This api will come in the next version

import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  // Url of the Identity Provider
  issuer: 'http://localhost:5000',

  // URL of the SPA to redirect the user to after login
  redirectUri: window.location.origin,

  // URL of the SPA to redirect the user after silent refresh
  logoutUrl: 'http://localhost:57100/default.aspx',

  // The SPA's id. The SPA is registerd with this id at the auth-server
  clientId: 'angular',

  // set the scope for the permissions the client should request
  // The first three are defined by OIDC. The 4th is a usecase-specific one
  scope: 'openid profile apiClient',

  // silentRefreshShowIFrame: true,

  showDebugInformation: true,

  sessionChecksEnabled: false,

  dummyClientSecret: 'secret'
};
