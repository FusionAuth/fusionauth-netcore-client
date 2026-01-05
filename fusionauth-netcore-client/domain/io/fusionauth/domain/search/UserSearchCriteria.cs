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

namespace io.fusionauth.domain.search
{

  /**
   * This class is the user query. It provides a build pattern as well as public fields for use on forms and in actions.
   *
   * @author Brian Pontarelli
   */
  public class UserSearchCriteria: BaseElasticSearchCriteria {

    public UserSearchCriteria with(Action<UserSearchCriteria> action) {
      action(this);
      return this;
    }
  }
}
