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

########################################################################
# DETAILS:  MUST NOT use default service account
# SEVERITY: Medium
# ASSET_TYPE: compute.googleapis.com/Instance
# TAGS: Defaults, Management, Compute Engine
########################################################################

package templates.google.compute.serviceAccount.default

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

asset_type = "compute.googleapis.com/Instance"

asset := input.asset

input_enriched := object.union({"resource": {"data": {"serviceAccounts": []}}}, asset)

params := lib.get_default(gparam.global_parameters, "compute", {})

deny[{
	"msg": "Disallowed default service account",
	"details": {"name": asset.name},
}] {
	not lib.asset_type_should_be_skipped(asset_type)

	account = input_enriched.resource.data.serviceAccounts[_]
	endswith(account.email, params.default_sa)
}
