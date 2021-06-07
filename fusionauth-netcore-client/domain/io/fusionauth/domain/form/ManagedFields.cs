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

namespace io.fusionauth.domain.form {

  /**
   * This class contains the managed fields that are also put into the database during FusionAuth setup.
   * <p>
   * NOTE TO FUSIONAUTH DEVS: These fields are are also declared in SQL in order to boot strap the system. These need to stay in sync.
   * - Any changes to these fields needs to also be reflected in mysql.sql and postgresql.sql
   *
   * @author Brian Pontarelli
   */
  public class ManagedFields {

    public ManagedFields with(Action<ManagedFields> action) {
      action(this);
      return this;
    }
  }
}
