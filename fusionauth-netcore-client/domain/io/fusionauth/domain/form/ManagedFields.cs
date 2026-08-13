/*
 * Copyright (c) 2018-2026, FusionAuth, All Rights Reserved
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

namespace io.fusionauth.domain.form
{

  /**
   * Contains the "managed"{@link FormField} keys. For these keys, FusionAuth controls the
   * field's control and data type.
   * <p>
   * The data type is always enforced, on both create and update.  The control is only defaulted
   * when omitted on create, and is otherwise left as submitted - it is not validated against
   * the managed definition. Once created, a mismatched control can only be fixed by deleting
   * and recreating the field, since updates always keep the field's existing control.
   * <p>
   * Internal Note: These fields are also declared in SQL in order to bootstrap the system. These need to stay in sync.
   * Any changes to these fields needs to also be reflected in mysql.sql and postgresql.sql
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
