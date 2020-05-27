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
   * JWT Configuration. A JWT Configuration for an Application may not be active if it is using the global configuration, the configuration
   * may be <code>enabled = false</code>.
   *
   * @author Daniel DeGroff
   */
  public class JWTConfiguration: Enableable {

    public Guid? accessTokenKeyId;

    public Guid? idTokenKeyId;

    public RefreshTokenExpirationPolicy refreshTokenExpirationPolicy;

    public RefreshTokenRevocationPolicy refreshTokenRevocationPolicy;

    public int? refreshTokenTimeToLiveInMinutes;

    public RefreshTokenUsagePolicy refreshTokenUsagePolicy;

    public int? timeToLiveInSeconds;

    public JWTConfiguration with(Action<JWTConfiguration> action) {
      action(this);
      return this;
    }
  }
}
