/*
 * Copyright (c) 2018-2025, FusionAuth, All Rights Reserved
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


using io.fusionauth.converters.helpers;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.provider
{

  /**
   * @author Daniel DeGroff
   */
  public class AppleApplicationConfiguration: BaseIdentityProviderApplicationConfiguration {

    public string bundleId;

    public string buttonText;

    public Guid? keyId;

    public string scope;

    public string servicesId;

    public string teamId;

    public AppleApplicationConfiguration with(Action<AppleApplicationConfiguration> action) {
      action(this);
      return this;
    }
  }
}
