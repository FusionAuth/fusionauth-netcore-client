/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */


using System.Collections.Generic;
using System;

namespace io.fusionauth.domain
{

  public class Templates {

    public string accountEdit;

    public string accountIndex;

    public string accountTwoFactorDisable;

    public string accountTwoFactorEnable;

    public string accountTwoFactorIndex;

    public string accountWebAuthnAdd;

    public string accountWebAuthnDelete;

    public string accountWebAuthnIndex;

    public string confirmationRequired;

    public string emailComplete;

    public string emailSent;

    public string emailVerificationRequired;

    public string emailVerify;

    public string helpers;

    public string index;

    public string oauth2Authorize;

    public string oauth2AuthorizedNotRegistered;

    public string oauth2ChildRegistrationNotAllowed;

    public string oauth2ChildRegistrationNotAllowedComplete;

    public string oauth2CompleteRegistration;

    public string oauth2Consent;

    public string oauth2Device;

    public string oauth2DeviceComplete;

    public string oauth2Error;

    public string oauth2Logout;

    public string oauth2Passwordless;

    public string oauth2Register;

    public string oauth2StartIdPLink;

    public string oauth2TwoFactor;

    public string oauth2TwoFactorEnable;

    public string oauth2TwoFactorEnableComplete;

    public string oauth2TwoFactorMethods;

    public string oauth2Wait;

    public string oauth2WebAuthn;

    public string oauth2WebAuthnReauth;

    public string oauth2WebAuthnReauthEnable;

    public string passwordChange;

    public string passwordComplete;

    public string passwordForgot;

    public string passwordSent;

    public string phoneComplete;

    public string phoneSent;

    public string phoneVerificationRequired;

    public string phoneVerify;

    public string registrationComplete;

    public string registrationSent;

    public string registrationVerificationRequired;

    public string registrationVerify;

    public string samlv2Logout;

    public string unauthorized;

    public string emailSend;

    public string registrationSend;

    public Templates with(Action<Templates> action) {
      action(this);
      return this;
    }
  }
}
