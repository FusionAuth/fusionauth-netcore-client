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


using io.fusionauth.domain;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.api
{

  /**
   * User API request object.
   *
   * @author Brian Pontarelli
   */
  public class UserRequest: BaseEventRequest {

    public Guid? applicationId;

    public string currentPassword;

    public bool? disableDomainBlock;

    public bool? sendSetPasswordEmail;

    public SendSetPasswordIdentityType sendSetPasswordIdentityType;

    public bool? skipVerification;

    public User user;

    public List<string> verificationIds;

    public UserRequest with(Action<UserRequest> action) {
      action(this);
      return this;
    }
  }
}
