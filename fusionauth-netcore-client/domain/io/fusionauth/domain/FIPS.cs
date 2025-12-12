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


using System.Collections.Generic;
using System;

namespace io.fusionauth.domain
{

  /**
   * Determines if FusionAuth is in FIPS mode based on the system property <code>fusionauth.fips.enabled</code>. This can only be enabled once and
   * should be enabled when the VM starts or as close to that point as possible.
   * <p>
   * Once this has been enabled, it cannot be disabled.
   * <p>
   * This also provides some helpers for FIPS things such as password length requirements.
   *
   * @author Brian Pontarelli & Daniel DeGroff
   */
  public class FIPS {

    public FIPS with(Action<FIPS> action) {
      action(this);
      return this;
    }
  }
}
