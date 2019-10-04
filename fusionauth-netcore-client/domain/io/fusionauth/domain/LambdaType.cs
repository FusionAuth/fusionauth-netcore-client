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


using System.Runtime.Serialization;
using System.Collections.Generic;
using System;

namespace io.fusionauth.domain {

  /**
   * The types of lambdas that indicate how they are invoked by FusionAuth.
   *
   * @author Brian Pontarelli
   */
  public enum LambdaType {
              [EnumMember(Value = "populate")]
            JWTPopulate, 
              [EnumMember(Value = "reconcile")]
            OpenIDReconcile, 
              [EnumMember(Value = "reconcile")]
            SAMLv2Reconcile, 
              [EnumMember(Value = "populate")]
            SAMLv2Populate
  }
}
