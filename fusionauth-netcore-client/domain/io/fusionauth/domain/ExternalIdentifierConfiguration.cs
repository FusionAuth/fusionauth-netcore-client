/*
 * Copyright (c) 2018-2023, FusionAuth, All Rights Reserved
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

  /**
   * @author Daniel DeGroff
   */
  public class ExternalIdentifierConfiguration {

    public string authorizationGrantIdTimeToLiveInSeconds;

    public SecureGeneratorConfiguration changePasswordIdGenerator;

    public string changePasswordIdTimeToLiveInSeconds;

    public string deviceCodeTimeToLiveInSeconds;

    public SecureGeneratorConfiguration deviceUserCodeIdGenerator;

    public SecureGeneratorConfiguration emailVerificationIdGenerator;

    public string emailVerificationIdTimeToLiveInSeconds;

    public SecureGeneratorConfiguration emailVerificationOneTimeCodeGenerator;

    public string externalAuthenticationIdTimeToLiveInSeconds;

    public string loginIntentTimeToLiveInSeconds;

    public string oneTimePasswordTimeToLiveInSeconds;

    public SecureGeneratorConfiguration passwordlessLoginGenerator;

    public string passwordlessLoginTimeToLiveInSeconds;

    public SecureGeneratorConfiguration passwordlessShortCodeLoginGenerator;

    public string passwordlessShortCodeLoginTimeToLiveInSeconds;

    public string pendingAccountLinkTimeToLiveInSeconds;

    public SecureGeneratorConfiguration registrationVerificationIdGenerator;

    public string registrationVerificationIdTimeToLiveInSeconds;

    public SecureGeneratorConfiguration registrationVerificationOneTimeCodeGenerator;

    public string rememberOAuthScopeConsentChoiceTimeToLiveInSeconds;

    public string samlv2AuthNRequestIdTimeToLiveInSeconds;

    public SecureGeneratorConfiguration setupPasswordIdGenerator;

    public string setupPasswordIdTimeToLiveInSeconds;

    public string smsVerificationTimeToLiveInSeconds;

    public string trustTokenTimeToLiveInSeconds;

    public string twoFactorIdTimeToLiveInSeconds;

    public SecureGeneratorConfiguration twoFactorOneTimeCodeIdGenerator;

    public string twoFactorOneTimeCodeIdTimeToLiveInSeconds;

    public string twoFactorTrustIdTimeToLiveInSeconds;

    public string webAuthnAuthenticationChallengeTimeToLiveInSeconds;

    public string webAuthnRegistrationChallengeTimeToLiveInSeconds;

    public ExternalIdentifierConfiguration with(Action<ExternalIdentifierConfiguration> action) {
      action(this);
      return this;
    }
  }
}
