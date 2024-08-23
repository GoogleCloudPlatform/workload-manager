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

#######################################################################
# DETAILS: VPC should have global routing.
# SEVERITY: Medium
# ASSET_TYPE: compute.googleapis.com/Network
# TAGS: Management, Performance, Networking, Connectivity
########################################################################

package google.network.vpc.routing

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

asset := input.asset

deny[{
	"msg": message,
	"details": {"name": asset.name},
}] {

	routingMode := lib.get_default(asset.resource.data.routingConfig, "routingMode", null)
	routingMode != "GLOBAL"
	message := sprintf("VPC network is not configured for global routing (%v).", [asset.name])

}
