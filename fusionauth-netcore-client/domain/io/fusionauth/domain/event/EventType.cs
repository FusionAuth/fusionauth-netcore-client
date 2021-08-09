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


using System.Runtime.Serialization;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.@event {

  /**
   * Models the event types that FusionAuth produces.
   *
   * @author Brian Pontarelli
   */
  public enum EventType {
        [EnumMember(Value = "jwt.public-key.update")]
        JWTPublicKeyUpdate, 
        [EnumMember(Value = "jwt.refresh-token.revoke")]
        JWTRefreshTokenRevoke, 
        [EnumMember(Value = "jwt.refresh")]
        JWTRefresh, 
        [EnumMember(Value = "audit-log.create")]
        AuditLogCreate, 
        [EnumMember(Value = "event-log.create")]
        @EventLogCreate, 
        [EnumMember(Value = "kickstart.success")]
        KickstartSuccess, 
        [EnumMember(Value = "user.action")]
        UserAction, 
        [EnumMember(Value = "user.bulk.create")]
        UserBulkCreate, 
        [EnumMember(Value = "user.create")]
        UserCreate, 
        [EnumMember(Value = "user.create.complete")]
        UserCreateComplete, 
        [EnumMember(Value = "user.deactivate")]
        UserDeactivate, 
        [EnumMember(Value = "user.delete")]
        UserDelete, 
        [EnumMember(Value = "user.delete.complete")]
        UserDeleteComplete, 
        [EnumMember(Value = "user.loginId.duplicate.create")]
        UserLoginIdDuplicateOnCreate, 
        [EnumMember(Value = "user.loginId.duplicate.update")]
        UserLoginIdDuplicateOnUpdate, 
        [EnumMember(Value = "user.email.update")]
        UserEmailUpdate, 
        [EnumMember(Value = "user.email.verified")]
        UserEmailVerified, 
        [EnumMember(Value = "user.login.failed")]
        UserLoginFailed, 
        [EnumMember(Value = "user.login.new-device")]
        UserLoginNewDevice, 
        [EnumMember(Value = "user.login.success")]
        UserLoginSuccess, 
        [EnumMember(Value = "user.login.suspicious")]
        UserLoginSuspicious, 
        [EnumMember(Value = "user.password.breach")]
        UserPasswordBreach, 
        [EnumMember(Value = "user.password.reset.send")]
        UserPasswordResetSend, 
        [EnumMember(Value = "user.password.reset.start")]
        UserPasswordResetStart, 
        [EnumMember(Value = "user.password.reset.success")]
        UserPasswordResetSuccess, 
        [EnumMember(Value = "user.password.update")]
        UserPasswordUpdate, 
        [EnumMember(Value = "user.reactivate")]
        UserReactivate, 
        [EnumMember(Value = "user.registration.create")]
        UserRegistrationCreate, 
        [EnumMember(Value = "user.registration.create.complete")]
        UserRegistrationCreateComplete, 
        [EnumMember(Value = "user.registration.delete")]
        UserRegistrationDelete, 
        [EnumMember(Value = "user.registration.delete.complete")]
        UserRegistrationDeleteComplete, 
        [EnumMember(Value = "user.registration.update")]
        UserRegistrationUpdate, 
        [EnumMember(Value = "user.registration.update.complete")]
        UserRegistrationUpdateComplete, 
        [EnumMember(Value = "user.registration.verified")]
        UserRegistrationVerified, 
        [EnumMember(Value = "user.two-factor.method.add")]
        UserTwoFactorMethodAdd, 
        [EnumMember(Value = "user.two-factor.method.remove")]
        UserTwoFactorMethodRemove, 
        [EnumMember(Value = "user.update")]
        UserUpdate, 
        [EnumMember(Value = "user.update.complete")]
        UserUpdateComplete, 
        [EnumMember(Value = "test")]
        Test
  }
}
