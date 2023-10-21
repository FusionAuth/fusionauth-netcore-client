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

namespace io.fusionauth.domain.api.jwt
{

  /**
   * API response for refreshing a JWT with a Refresh Token.
   * <p>
   * Using a different response object from RefreshTokenResponse because the retrieve response will return an object for refreshToken, and this is a
   * string.
   *
   * @author Daniel DeGroff
   */
  public class JWTRefreshResponse {

    public string refreshToken;

    public Guid? refreshTokenId;

    public string token;

    public JWTRefreshResponse with(Action<JWTRefreshResponse> action) {
      action(this);
      return this;
    }
  }
}
