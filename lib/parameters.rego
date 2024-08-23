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

package validator.google.lib.parameters

# These are the default constraints applied to rules
# Feel free to edit these configurations for you use case if needed

global_parameters := {
	"must_have_labels": {"app","cost-center","env"},
	"compute": {
		"default_sa": "-compute@developer.gserviceaccount.com",
		"locations": [
			"us-central1-a",
			"us-east1-a",
		],
		"exemptions": [],
	},
	"cloud_kms": {
		"approved_protection": [],
		"approved_key_rotation_time": "7776000s",
		"exemptions": [],
	},
	"cloud_storage": {
		"public_access_prevention": "enforced",
		"lifecycle_rule_class_classification": ["MULTI_REGIONAL", "REGIONAL"],
		"exemptions": [],
	},
	"iam": {
		"serviceAccountKeyExpireDays": 90,
		"exemptions": [],
	},
}
