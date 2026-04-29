/*
 * Copyright (c) 2018-2026, FusionAuth, All Rights Reserved
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

namespace io.fusionauth.domain.provider
{

  /**
   * The results of an identity provider connection test.
   */
  public class IdentityProviderConnectionTestResult {

    public string email;

    public Guid? identityProviderId;

    public string identityProviderUserId;

    public DateTimeOffset? startInstant;

    public List<IdentityProviderLoginStep> steps;

    public bool? success;

    public string username;

    public IdentityProviderConnectionTestResult with(Action<IdentityProviderConnectionTestResult> action) {
      action(this);
      return this;
    }
  }
}
