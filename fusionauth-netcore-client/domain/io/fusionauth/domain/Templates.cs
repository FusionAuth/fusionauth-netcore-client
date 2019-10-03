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

  public class Templates {
    public string emailComplete;
    public string emailSend;
    public string emailVerify;
    public string helpers;
    public string oauth2Authorize;
    public string oauth2ChildRegistrationNotAllowed;
    public string oauth2ChildRegistrationNotAllowedComplete;
    public string oauth2CompleteRegistration;
    public string oauth2Error;
    public string oauth2Logout;
    public string oauth2Passwordless;
    public string oauth2Register;
    public string oauth2TwoFactor;
    public string passwordChange;
    public string passwordComplete;
    public string passwordForgot;
    public string passwordSent;
    public string registrationComplete;
    public string registrationSend;
    public string registrationVerify;

    public Templates with(Action<Templates> action) {
      action(this);
      return this;
    }
  }
}
