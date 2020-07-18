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
   * @author Daniel DeGroff
   */
  public class SecureIdentity {

    public DateTimeOffset? breachedPasswordLastCheckedInstant;

    public BreachedPasswordStatus breachedPasswordStatus;

    public Guid? connectorId;

    public string encryptionScheme;

    public int? factor;

    public Guid? id;

    public DateTimeOffset? lastLoginInstant;

    public string password;

    public ChangePasswordReason passwordChangeReason;

    public bool? passwordChangeRequired;

    public DateTimeOffset? passwordLastUpdateInstant;

    public string salt;

    public TwoFactorDelivery twoFactorDelivery;

    public bool? twoFactorEnabled;

    public string twoFactorSecret;

    public string username;

    public ContentStatus usernameStatus;

    public bool? verified;

    public SecureIdentity with(Action<SecureIdentity> action) {
      action(this);
      return this;
    }
  }
}
