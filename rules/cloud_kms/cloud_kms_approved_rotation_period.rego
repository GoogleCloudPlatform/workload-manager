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
# DETAILS:  Ensure appropriate key rotation is set
# SEVERITY: High
# ASSET_TYPE: cloudkms.googleapis.com/CryptoKey
# TAGS: Cloud KMS, Manageability, Operations, Security
########################################################################

package google.kms.approved.rotation.period

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

	# The rotation period for a key may be "never".  This results
	# in the rotationPeriod attribute to be omitted from response
	# from the CAI.  The default is 99999999s.  This is
	# sufficiently high enough to cause fail
	# default max 90days or 7776000s

	approved_key_rotation_time := lib.get_default(params, "approved_key_rotation_time", "7776000s")
	current_rotation_period := lib.get_default(asset.resource.data, "rotationPeriod", "99999999s")

	time.parse_duration_ns(current_rotation_period) > time.parse_duration_ns(approved_key_rotation_time)

	message := sprintf("%v: CMEK Rotation Period must be at most %v. Current setting: %v", [asset.name, approved_key_rotation_time, current_rotation_period])
	metadata := {"name": asset.name}
}
