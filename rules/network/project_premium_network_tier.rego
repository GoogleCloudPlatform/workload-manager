Copyright 2024 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

#######################################################################
# DETAILS: Project should have premium network tier.
# SEVERITY: Medium
# ASSET_TYPE: compute.googleapis.com/Project
# TAGS: Management, Performance, Networking
########################################################################

package templates.google.network.premiumNetwork

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

asset_type = "compute.googleapis.com/Project"

asset := input.asset

deny[{
	"msg": message,
	"details": {"name": asset.name},
}] {
	not lib.asset_type_should_be_skipped(asset_type)

	asset.resource.data.defaultNetworkTier != "PREMIUM"

	message := sprintf("Project is not configured for premium network tier (%v).", [asset.name])
}
