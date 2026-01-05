/*
 * Copyright (c) FusionAuth, All Rights Reserved
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


using io.fusionauth.domain.api;
using io.fusionauth.domain;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.api.twoFactor
{

  /**
   * Check the status of two-factor authentication for a user, with more options than on a GET request.
   */
  public class TwoFactorStatusRequest: BaseEventRequest {

    public Guid? userId;

    public string accessToken;

    public MultiFactorAction action;

    public Guid? applicationId;

    public string twoFactorTrustId;

    public TwoFactorStatusRequest with(Action<TwoFactorStatusRequest> action) {
      action(this);
      return this;
    }
  }
}
