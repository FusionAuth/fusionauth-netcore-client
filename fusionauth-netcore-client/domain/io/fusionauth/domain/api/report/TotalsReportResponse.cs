/*
 * Copyright (c) 2018-2023, FusionAuth, All Rights Reserved
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

namespace io.fusionauth.domain.api.report {

  /**
   * The response from the total report. This report stores the total numbers for each application.
   *
   * @author Brian Pontarelli
   */
  public class TotalsReportResponse {

    public IDictionary<Guid, Totals> applicationTotals;

    public long? globalRegistrations;

    public long? totalGlobalRegistrations;

    public TotalsReportResponse with(Action<TotalsReportResponse> action) {
      action(this);
      return this;
    }
  }
}
