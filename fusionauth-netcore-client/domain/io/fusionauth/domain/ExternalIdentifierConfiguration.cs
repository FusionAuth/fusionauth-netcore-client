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

namespace io.fusionauth.domain {

  /**
   * @author Daniel DeGroff
   */
  public class ExternalIdentifierConfiguration {

    public int? authorizationGrantIdTimeToLiveInSeconds;

    public SecureGeneratorConfiguration changePasswordIdGenerator;

    public int? changePasswordIdTimeToLiveInSeconds;

    public int? deviceCodeTimeToLiveInSeconds;

    public SecureGeneratorConfiguration deviceUserCodeIdGenerator;

    public SecureGeneratorConfiguration emailVerificationIdGenerator;

    public int? emailVerificationIdTimeToLiveInSeconds;

    public SecureGeneratorConfiguration emailVerificationOneTimeCodeGenerator;

    public int? externalAuthenticationIdTimeToLiveInSeconds;

    public int? oneTimePasswordTimeToLiveInSeconds;

    public SecureGeneratorConfiguration passwordlessLoginGenerator;

    public int? passwordlessLoginTimeToLiveInSeconds;

    public int? pendingAccountLinkTimeToLiveInSeconds;

    public SecureGeneratorConfiguration registrationVerificationIdGenerator;

    public int? registrationVerificationIdTimeToLiveInSeconds;

    public SecureGeneratorConfiguration registrationVerificationOneTimeCodeGenerator;

    public int? samlv2AuthNRequestIdTimeToLiveInSeconds;

    public SecureGeneratorConfiguration setupPasswordIdGenerator;

    public int? setupPasswordIdTimeToLiveInSeconds;

    public int? trustTokenTimeToLiveInSeconds;

    public int? twoFactorIdTimeToLiveInSeconds;

    public SecureGeneratorConfiguration twoFactorOneTimeCodeIdGenerator;

    public int? twoFactorOneTimeCodeIdTimeToLiveInSeconds;

    public int? twoFactorTrustIdTimeToLiveInSeconds;

    public int? webAuthnAuthenticationChallengeTimeToLiveInSeconds;

    public int? webAuthnRegistrationChallengeTimeToLiveInSeconds;

    public ExternalIdentifierConfiguration with(Action<ExternalIdentifierConfiguration> action) {
      action(this);
      return this;
    }
  }
}
