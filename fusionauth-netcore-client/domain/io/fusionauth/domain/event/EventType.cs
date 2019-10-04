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
              [EnumMember(Value = "user.delete")]
            UserDelete, 
              [EnumMember(Value = "user.create")]
            UserCreate, 
              [EnumMember(Value = "user.update")]
            UserUpdate, 
              [EnumMember(Value = "user.deactivate")]
            UserDeactivate, 
              [EnumMember(Value = "user.bulk.create")]
            UserBulkCreate, 
              [EnumMember(Value = "user.reactivate")]
            UserReactivate, 
              [EnumMember(Value = "user.action")]
            UserAction, 
              [EnumMember(Value = "jwt.refresh-token.revoke")]
            JWTRefreshTokenRevoke, 
              [EnumMember(Value = "jwt.public-key.update")]
            JWTPublicKeyUpdate, 
              [EnumMember(Value = "user.login.success")]
            UserLoginSuccess, 
              [EnumMember(Value = "user.login.failed")]
            UserLoginFailed, 
              [EnumMember(Value = "user.registration.create")]
            UserRegistrationCreate, 
              [EnumMember(Value = "user.registration.update")]
            UserRegistrationUpdate, 
              [EnumMember(Value = "user.registration.delete")]
            UserRegistrationDelete, 
              [EnumMember(Value = "user.registration.verified")]
            UserRegistrationVerified, 
              [EnumMember(Value = "user.email.verified")]
            UserEmailVerified, 
              [EnumMember(Value = "test")]
            Test
  }
}
