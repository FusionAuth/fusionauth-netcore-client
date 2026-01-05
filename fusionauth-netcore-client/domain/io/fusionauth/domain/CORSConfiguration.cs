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


using io.fusionauth.domain.util;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain
{

  /**
   * @author Trevor Smith
   */
  public class CORSConfiguration: Enableable {

    public bool? allowCredentials;

    public List<string> allowedHeaders;

    public List<HTTPMethod> allowedMethods;

    public List<string> allowedOrigins;

    public bool? debug;

    public List<string> exposedHeaders;

    public int? preflightMaxAgeInSeconds;

    public CORSConfiguration with(Action<CORSConfiguration> action) {
      action(this);
      return this;
    }
  }
}
