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


using io.fusionauth.domain;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain.oauth2
{

  /**
   * @author Daniel DeGroff
   */
  public class OAuthError {

    public string change_password_id;

    public string error_description;

    public OAuthErrorType error;

    public string error_uri;

    public List<TwoFactorMethod> two_factor_methods;

    public OAuthErrorReason error_reason;

    public string two_factor_id;

    public OAuthError with(Action<OAuthError> action) {
      action(this);
      return this;
    }
  }
}
