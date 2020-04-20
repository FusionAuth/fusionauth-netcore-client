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

namespace io.fusionauth.domain.@event {

  /**
   * Models the JWT Refresh Event. This event will be fired when a JWT is "refreshed" (generated) using a Refresh Token.
   *
   * @author Daniel DeGroff
   */
  public class JWTRefreshEvent: BaseEvent {

    public Guid? applicationId;

    public string original;

    public string refreshToken;

    public string token;

    public Guid? userId;

    public JWTRefreshEvent with(Action<JWTRefreshEvent> action) {
      action(this);
      return this;
    }
  }
}
