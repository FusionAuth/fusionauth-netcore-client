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
  public class LinkedInIdentityProvider: BaseIdentityProvider<LinkedInApplicationConfiguration> {

    public string buttonText;

    public string client_id;

    public string client_secret;

    public string scope;

    public LinkedInIdentityProvider with(Action<LinkedInIdentityProvider> action) {
      action(this);
      return this;
    }
  }
}
