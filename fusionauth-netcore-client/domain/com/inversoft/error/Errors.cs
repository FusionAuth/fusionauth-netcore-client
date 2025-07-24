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

namespace com.inversoft.error
{

  /**
   * Standard error domain object that can also be used as the response from an API call.
   *
   * @author Brian Pontarelli
   */
  public class Errors {

    public IDictionary<string, List<Error>> fieldErrors;

    public List<Error> generalErrors;

    public Errors with(Action<Errors> action) {
      action(this);
      return this;
    }
  }
}
