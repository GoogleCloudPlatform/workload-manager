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
# DETAILS:  Ensure Disk are auto deleted on Instance delete to reduce cost
# SEVERITY: High
# ASSET_TYPE: compute.googleapis.com/Instance
# TAGS: Cost, Management, Disk
########################################################################

package templates.google.compute.instance.disk.autodelete

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

service_name = "compute"

asset := input.asset

asset_type := "compute.googleapis.com/Instance"

deny[{
	"msg": "autoDelete set to off",
	"details": {"name": asset.name},
}] {
	not lib.asset_type_should_be_skipped(asset_type)
	autoDelete := lib.get_default(asset.resource.data.disks, "autoDelete", false)
	autoDelete != true
}
