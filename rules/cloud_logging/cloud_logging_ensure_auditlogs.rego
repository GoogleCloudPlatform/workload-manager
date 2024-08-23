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
# DETAILS:  Verify that all Admin Activity Logs are stored and managed. Admin activity logs are stored in the '_Required' log bucket for 400 days by default (free), so no separate sink configuration is needed. If Admin Activity Logs are managed by creating a separate sink (paid), check the sink settings to ensure that is set to [resource.type=\"project\" OR \"service_account\" OR \"iam_role\" logName=\"projects/$[PROJECT_ID]/logs/cloudaudit.googleapis.com%2Factivity\"].
# SEVERITY: High
# ASSET_TYPE: logging.googleapis.com/LogSink
# TAGS: Logging, Security, Audit, Compliance
#########################################

package google.logging.admin_activity_logs

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

asset := input.asset

params := lib.get_default(gparam.global_parameters, "logging", {})

# Verify that Admin Activity Logs are stored for at least 400 days
deny [{"msg": message, "details": metadata}] {

  # Verify filter for admin activity logs
  # Check if the sink filter matches the recommended filter for Admin Activity logs

  expected_filter := "cloudaudit.googleapis.com%%2Factivity"
  not contains(asset.resource.data.filter, expected_filter)

  message := sprintf("LogSink '%s' does not have the correct filter for Admin Activity logs. Expected metric in filter: '%s'", [asset.name, expected_filter])
  metadata := {"name": asset.name}
}
