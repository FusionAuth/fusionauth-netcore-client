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

namespace io.fusionauth.domain.api.user {

  /**
   * Forgot password request object.
   *
   * @author Brian Pontarelli
   */
  public class ForgotPasswordRequest {

    public Guid? applicationId;

    public string changePasswordId;

    public string email;

    public string loginId;

    public bool? sendForgotPasswordEmail;

    public IDictionary<string, object> state;

    public string username;

    public ForgotPasswordRequest with(Action<ForgotPasswordRequest> action) {
      action(this);
      return this;
    }
  }
}
