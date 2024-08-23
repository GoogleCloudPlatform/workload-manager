# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#########################################
# DETAILS: Ensure that Admin Activity Logs are stored for at least one year. These are stored in the '_Required' log bucket for 400 days by default (free).
# SEVERITY: High
# ASSET_TYPE: logging.googleapis.com/LogBucket
# TAGS: Logging, Security, Audit, Compliance
#########################################

package google.logging.logbucket.admin_activity_logs_retention

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

asset := input.asset

params := lib.get_default(gparam.global_parameters, "logging", {})

# Verify that Admin Activity Logs are stored for at least 400 days
deny [{"msg": message, "details": metadata}] {

    # This rule only applies to the '_Required' log bucket.
    asset.resource.data.name == sprintf("%v/locations/%v/buckets/_Required", [asset.resource.parent, asset.resource.location])

    retention_days := lib.get_default(asset.resource.data, "retentionDays", 0)

    # Check if retention days are less than 400
    retention_days < 400

    message := sprintf("The '_Required' log bucket must have a retention period of at least 400 days. Current retention: %v days", [retention_days])
}
