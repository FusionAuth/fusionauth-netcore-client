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
   * User registration information for a single application.
   *
   * @author Brian Pontarelli
   */
  public class UserRegistration {

    public IDictionary<string, object> data;

    public List<string> preferredLanguages;

    public IDictionary<string, string> tokens;

    public Guid? applicationId;

    public string authenticationToken;

    public Guid? cleanSpeakId;

    public Guid? id;

    public DateTimeOffset? insertInstant;

    public DateTimeOffset? lastLoginInstant;

    public DateTimeOffset? lastUpdateInstant;

    public List<string> roles;

    public string timezone;

    public string username;

    public ContentStatus usernameStatus;

    public bool? verified;

    public UserRegistration with(Action<UserRegistration> action) {
      action(this);
      return this;
    }
  }
}
