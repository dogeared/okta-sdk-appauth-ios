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

open class OktaTokenManager: NSObject {

    private var _idToken: String? = nil

    open var authState: OIDAuthState
    open var issuer: String
    open var clientId: String

    open var idToken: String? {
        get { return self._idToken }
    }

    open var refreshToken: String? {
        get {
            guard let token = self.authState.refreshToken else { return nil }
            return token
        }
    }

    open var accessToken: String? {
        get {
            guard let token = self.authState.lastTokenResponse?.accessToken else { return nil }
            return token
        }
    }

    public init(authState: OIDAuthState, issuer: String, clientId: String) {
        self.authState = authState
        self.issuer = issuer
        self.clientId = clientId

        super.init()

        // Since the idToken isn't stored in the last tokenResponse after refresh,
        // refer to the cached keychain version.
        if let prevIdToken = authState.lastTokenResponse?.idToken {
            self._idToken = prevIdToken
            try? Vinculum.set(key: "idToken", value: prevIdToken)
        } else {
            guard let prevIdToken = try? Vinculum.get("idToken")?.getString() else {
                self._idToken = nil
                return
            }
            self._idToken = prevIdToken
        }

        OktaAuth.tokens = self

        // Encode and store the current auth state
        let authStateData = NSKeyedArchiver.archivedData(withRootObject: authState)
        self.setData(value: authStateData, forKey: "OktaAuthState")

        // Store the current configuration
        let config = [ "issuer": issuer, "clientId": clientId ]
        let configData = NSKeyedArchiver.archivedData(withRootObject: config)
        self.setData(value: configData, forKey: "OktaAuthConfig")

        OktaAuth.configuration = config
    }

    public func setData(value: Data, forKey: String) {
        self.setData(value: value, forKey: forKey, needsBackgroundAccess: false)
    }

    public func setData(value: Data, forKey: String, needsBackgroundAccess: Bool) {
        var accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        if needsBackgroundAccess {
            // If the device needs background keychain access, grant permission
            accessibility = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        do {
            try Vinculum.set(key: forKey, value: value, accessibility: accessibility)
        } catch let error {
            // Log the error until this method is updated to throw
            print(error.localizedDescription)
        }
    }

    public func set(value: String, forKey: String) {
        // Default to not allowing background access for keychain
        self.set(value: value, forKey: forKey, needsBackgroundAccess: false)
    }

    public func set(value: String, forKey: String, needsBackgroundAccess: Bool) {
        var accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        if needsBackgroundAccess {
            // If the device needs background keychain access, grant permission
            accessibility = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }

        do {
            try Vinculum.set(key: forKey, value: value, accessibility: accessibility)
        } catch let error {
            // Log the error until this method is updated to throw
            print(error.localizedDescription)
        }
    }

    public func get(forKey: String) -> String? {
        // Attempt to return the string value of the stored key
        do {
            if let keychainItem =  try Vinculum.get(forKey) {
                return keychainItem.getString()
            }
        } catch let error {
            // Log the error until this method is updated to throw
            print(error.localizedDescription)
        }
        return nil
    }

    public func clear() {
        Vinculum.removeAll()
        OktaAuth.tokens = nil
    }
}
