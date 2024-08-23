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
# DETAILS:  Ensure Cloud SQL is in approved location
# SEVERITY: High
# ASSET_TYPE: sqladmin.googleapis.com/Instance
# TAGS: Cloud SQL, Location, Reliability
########################################################################

package google.sql.instance.approved.location

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

	#Check if set region is in allowed locations
	approved_locations := lib.get_default(params, "locations", [])
	asset_location := lib.get_default(asset.resource.data, "region", "")

	found := {asset_location} & {x | x := approved_locations[_]}
	not count(found) != 0

	message := sprintf("%v is in a disallowed location (%v). Allowed regions :  %v", [asset.name, asset_location, approved_locations])

	metadata := {"name": asset.name}
}
