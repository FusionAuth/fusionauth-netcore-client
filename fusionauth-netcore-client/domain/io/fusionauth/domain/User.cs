/*
 * Copyright (c) 2018-2022, FusionAuth, All Rights Reserved
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
   * The global view of a User. This object contains all global information about the user including birth date, registration information
   * preferred languages, global attributes, etc.
   *
   * @author Seth Musselman
   */
  public class User: SecureIdentity {

    public List<string> preferredLanguages;

    public bool? active;

    public string birthDate;

    public Guid? cleanSpeakId;

    public IDictionary<string, object> data;

    public string email;

    public DateTimeOffset? expiry;

    public string firstName;

    public string fullName;

    public string imageUrl;

    public DateTimeOffset? insertInstant;

    public string lastName;

    public DateTimeOffset? lastUpdateInstant;

    public string middleName;

    public string mobilePhone;

    public string parentEmail;

    public Guid? tenantId;

    public string timezone;

    public UserTwoFactorConfiguration twoFactor;

    public List<GroupMember> memberships;

    public List<UserRegistration> registrations;

    public User with(Action<User> action) {
      action(this);
      return this;
    }
  }
}
