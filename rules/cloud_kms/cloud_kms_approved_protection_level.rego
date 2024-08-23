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
# DETAILS:  Ensure approved protection is configured.
# SEVERITY: High
# ASSET_TYPE: cloudkms.googleapis.com/CryptoKey
# TAGS: Cloud KMS, Manageability, Operations, Security
########################################################################

package google.kms.approved.protection

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

asset := input.asset

params := lib.get_default(gparam.global_parameters, "cloud_kms", {})

deny [{"msg": message, "details": metadata}] {
	# Check if resource is in exempt list
	exempt_list := lib.get_default(params, "exemptions", [])
	exempt := {asset.name} & {ex | ex := exempt_list[_]}
	not count(exempt) != 0

	#Check if using approved algorithm
	approved_protection := lib.get_default(params, "approved_protection", [])
	current_protection := lib.get_default(asset.resource.data.versionTemplate, "protectionLevel", "")

	found := {current_protection} & {x | x := approved_protection[_]}
	not count(found) != 0

	message := sprintf("%v not using approved algorithms purpose encrypt/decrypt. Current setting: %v", [asset.name, current_protection])
	metadata := {"name": asset.name}
}
