/*
 * Copyright (c) 2018, FusionAuth, All Rights Reserved
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
   * @author Brian Pontarelli
   */
  public class EmailConfiguration {

    public string defaultFromEmail;

    public string defaultFromName;

    public Guid? emailUpdateEmailTemplateId;

    public Guid? emailVerifiedEmailTemplateId;

    public Guid? forgotPasswordEmailTemplateId;

    public string host;

    public Guid? loginIdInUseOnCreateEmailTemplateId;

    public Guid? loginIdInUseOnUpdateEmailTemplateId;

    public Guid? loginNewDeviceEmailTemplateId;

    public Guid? loginSuspiciousEmailTemplateId;

    public string password;

    public Guid? passwordResetSuccessEmailTemplateId;

    public Guid? passwordUpdateEmailTemplateId;

    public Guid? passwordlessEmailTemplateId;

    public int? port;

    public string properties;

    public EmailSecurityType security;

    public Guid? setPasswordEmailTemplateId;

    public Guid? twoFactorMethodAddEmailTemplateId;

    public Guid? twoFactorMethodRemoveEmailTemplateId;

    public EmailUnverifiedOptions unverified;

    public string username;

    public Guid? verificationEmailTemplateId;

    public VerificationStrategy verificationStrategy;

    public bool? verifyEmail;

    public bool? verifyEmailWhenChanged;

    public EmailConfiguration with(Action<EmailConfiguration> action) {
      action(this);
      return this;
    }
  }
}
