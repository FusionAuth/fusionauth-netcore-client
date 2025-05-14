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
   * Hold tenant phone configuration for passwordless and verification cases.
   *
   * @author Brady Wied
   */
  public class TenantPhoneConfiguration {

    public Guid? forgotPasswordTemplateId;

    public Guid? identityUpdateTemplateId;

    public bool? @implicitPhoneVerificationAllowed;

    public Guid? loginIdInUseOnCreateTemplateId;

    public Guid? loginIdInUseOnUpdateTemplateId;

    public Guid? loginNewDeviceTemplateId;

    public Guid? loginSuspiciousTemplateId;

    public Guid? messengerId;

    public Guid? passwordResetSuccessTemplateId;

    public Guid? passwordUpdateTemplateId;

    public Guid? passwordlessTemplateId;

    public Guid? setPasswordTemplateId;

    public Guid? twoFactorMethodAddTemplateId;

    public Guid? twoFactorMethodRemoveTemplateId;

    public PhoneUnverifiedOptions unverified;

    public Guid? verificationCompleteTemplateId;

    public VerificationStrategy verificationStrategy;

    public Guid? verificationTemplateId;

    public bool? verifyPhoneNumber;

    public TenantPhoneConfiguration with(Action<TenantPhoneConfiguration> action) {
      action(this);
      return this;
    }
  }
}
