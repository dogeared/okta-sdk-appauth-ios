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

    open var authState: OIDAuthState?
    open var idToken: String?
    open var refreshToken: String?
    open var accessToken: String?

    public init(authState: OIDAuthState?) {
        super.init()

        if authState == nil { return }
        self.authState = authState!
        self.accessToken = authState?.lastTokenResponse?.accessToken
        self.idToken = authState?.lastTokenResponse?.idToken
        self.refreshToken = authState?.lastTokenResponse?.refreshToken

        OktaAuth.tokens = self

        // Encode and store the current auth state
        let authStateData = NSKeyedArchiver.archivedData(withRootObject: authState!)
        self.setData(value: authStateData, forKey: "appAuthState")
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
