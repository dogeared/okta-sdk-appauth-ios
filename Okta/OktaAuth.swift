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
import Vinculum

public struct OktaAuthorization {

    func authCodeFlow(_ config: [String: Any], view: UIViewController,
                      callback: @escaping (OktaTokenManager?, OktaError?) -> Void) {
        // Discover Endpoints
        getMetadataConfig(URL(string: config["issuer"] as! String)) { oidConfig, error in
            if error != nil {
                return callback(nil, error!)
            }

            // Build the Authentication request
            let request = OIDAuthorizationRequest(
                       configuration: oidConfig!,
                            clientId: config["clientId"] as! String,
                              scopes: Utils.scrubScopes(config["scopes"]),
                         redirectURL: URL(string: config["redirectUri"] as! String)!,
                        responseType: OIDResponseTypeCode,
                additionalParameters: nil
            )

            // Start the authorization flow
            OktaAuth.currentAuthorizationFlow = OIDAuthState.authState(byPresenting: request, presenting: view){
                authorizationResponse, error in
                
                if let response = authorizationResponse {
                    // Return the tokens
                    let tokenManager = OktaTokenManager(
                        authState: response,
                           issuer: config["issuer"] as! String,
                         clientId: config["clientId"] as! String
                    )

                    // Set the local cache and write to storage
                    self.storeAuthState(tokenManager)
                    callback(tokenManager, nil)
                } else {
                    callback(nil, .APIError("Authorization Error: \(error!.localizedDescription)"))
                }
            }
        }
    }

    func passwordFlow(_ config: [String: Any], credentials: [String: String]?, view: UIViewController,
                      callback: @escaping (OktaTokenManager?, OktaError?) -> Void) {
        // Discover Endpoints
        getMetadataConfig(URL(string: config["issuer"] as! String)) { oidConfig, error in
            if error != nil {
                return callback(nil, error!)
            }

            // Build the Authentication request
            let request = OIDTokenRequest(
                           configuration: oidConfig!,
                               grantType: OIDGrantTypePassword,
                       authorizationCode: nil,
                             redirectURL: URL(string: config["redirectUri"] as! String)!,
                                clientID: config["clientId"] as! String,
                            clientSecret: (config["clientSecret"] as! String),
                                   scope: Utils.scrubScopes(config["scopes"]).joined(separator: " "),
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

                    let tokenManager = OktaTokenManager(
                        authState: authState,
                           issuer: config["issuer"] as! String,
                         clientId: config["clientId"] as! String
                    )

                    // Set the local cache and write to storage
                    self.storeAuthState(tokenManager)
                    callback(tokenManager, nil)
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
            // Cache the well-known endpoint response
            OktaAuth.wellKnown = dictResponse
            return callback(OIDServiceConfiguration(discoveryDocument: oidcConfig), nil)
        }
    }
    
    func storeAuthState(_ tokenManager: OktaTokenManager) {
        // Encode and store the current auth state and
        // cache the current tokens
        OktaAuth.tokens = tokenManager

        let authStateData = NSKeyedArchiver.archivedData(withRootObject: tokenManager)
        do {
            try Vinculum.set(key: "OktaAuthStateTokenManager", value: authStateData, accessibility: tokenManager.accessibility)
        } catch let error {
            print("Error: \(error)")
        }
    }
}
