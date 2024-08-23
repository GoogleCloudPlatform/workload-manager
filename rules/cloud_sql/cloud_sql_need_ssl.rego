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

########################################################################
# DETAILS:  Ensure SSL is enabled on SQL instance. Only allow connections encrypted with SSL/TLS and with valid client certificates.
# SEVERITY: High
# ASSET_TYPE: sqladmin.googleapis.com/Instance
# TAGS: Cloud SQL, Operations, Security, Networking
########################################################################

package google.sql.instance.requiressl

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

asset := input.asset

params := lib.get_default(gparam.global_parameters, "cloudsql", {})

deny [{"msg": message, "details": metadata}] {
	# Check if resource is in exempt list
	exempt_list := lib.get_default(params, "exemptions", [])
	exempt := {asset.name} & {ex | ex := exempt_list[_]}
	not count(exempt) != 0

	requireSsl := lib.get_default(asset.resource.data.settings.ipConfiguration, "requireSsl", null)
	requireSsl != true

	message := sprintf("%v has networks with SSL settings in violation of policy. Current value: %v", [asset.name, requireSsl])
	metadata := {"resource": asset.name}
}