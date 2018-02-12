/*
 * Copyright (c) 2017, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

import AppAuth

public struct OktaAuthorization {

    func authCodeFlow(_ config: [String: String], view: UIViewController,
                      callback: @escaping (OktaTokenManager?, OktaError?) -> Void) {
        // Discover Endpoints
        guard let issuer = config["issuer"],
            let clientId = config["clientId"],
            let redirectUri = config["redirectUri"] else {
            return callback(nil, .MissingConfigurationValues)
        }

        getMetadataConfig(URL(string: issuer)) { oidConfig, error in
            if error != nil {
                return callback(nil, error!)
            }

            // Build the Authentication request
            let request = OIDAuthorizationRequest(
                       configuration: oidConfig!,
                            clientId: clientId,
                              scopes: Utils.scrubScopes(config["scopes"]),
                         redirectURL: URL(string: redirectUri)!,
                        responseType: OIDResponseTypeCode,
                additionalParameters: nil
            )

            // Start the authorization flow
            OktaAuth.currentAuthorizationFlow = OIDAuthState.authState(byPresenting: request, presenting: view){
                authorizationResponse, error in
                
                if authorizationResponse != nil {
                    // Return the tokens
                    callback(OktaTokenManager(authState: authorizationResponse), nil)
                } else {
                    callback(nil, .APIError("Authorization Error: \(error!.localizedDescription)"))
                }
            }
        }
    }

    func passwordFlow(_ config: [String: String], credentials: [String: String]?, view: UIViewController,
                      callback: @escaping (OktaTokenManager?, OktaError?) -> Void) {
        // Discover Endpoints
        guard let issuer = config["issuer"],
            let clientId = config["clientId"],
            let clientSecret = config["clientSecret"],
            let redirectUri = config["redirectUri"] else {
                return callback(nil, .MissingConfigurationValues)
        }

        getMetadataConfig(URL(string: issuer)) { oidConfig, error in
            if error != nil {
                return callback(nil, error!)
            }

            // Build the Authentication request
            let request = OIDTokenRequest(
                       configuration: oidConfig!,
                           grantType: OIDGrantTypePassword,
                   authorizationCode: nil,
                         redirectURL: URL(string: redirectUri)!,
                            clientID: clientId,
                        clientSecret: clientSecret,
                              scopes: Utils.scrubScopes(config["scopes"]),
                        refreshToken: nil,
                        codeVerifier: nil,
                additionalParameters: credentials
            )

            // Start the authorization flow
            OIDAuthorizationService.perform(request) { authorizationResponse, responseError in
                if responseError != nil {
                    callback(nil, .APIError("Authorization Error: \(responseError!.localizedDescription)"))
                }

                if authorizationResponse != nil {
                    // Return the tokens
                    let authState = OIDAuthState(
                            authorizationResponse: nil,
                                    tokenResponse: authorizationResponse,
                             registrationResponse: nil
                        )
                    callback(OktaTokenManager(authState: authState), nil)
                }
            }
        }
    }

    func getMetadataConfig(_ issuer: URL?, callback: @escaping (OIDServiceConfiguration?, OktaError?) -> Void) {
        // Get the metadata from the discovery endpoint
        guard let issuer = issuer, let configUrl = URL(string: "\(issuer)/.well-known/openid-configuration") else {
            return callback(nil, .NoDiscoveryEndpoint)
        }

        OktaApi.get(configUrl, headers: nil) { response, error in
            guard let dictResponse = response, let oidcConfig = try? OIDServiceDiscovery(dictionary: dictResponse) else {
                let responseError =
                    "Error returning discovery document:" +
                    "\(error!.localizedDescription) Please" +
                    "check your PList configuration"
                return callback(nil, .APIError(responseError))
            }
            return callback(OIDServiceConfiguration(discoveryDocument: oidcConfig), nil)
        }
    }
}
