/*
 * Copyright (c) FusionAuth, All Rights Reserved
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

namespace io.fusionauth.domain
{

  /**
   * A Tenant-level policy for deleting Users.
   *
   * @author Trevor Smith
   */
  public class TenantUserDeletePolicy {

    public TimeBasedDeletePolicy unverified;

    public TenantUserDeletePolicy with(Action<TenantUserDeletePolicy> action) {
      action(this);
      return this;
    }
  }
}
