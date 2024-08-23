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
# DETAILS:  Service Account Key expiration time should not be older than 90 days or as defined in params file.
# SEVERITY: Medium
# ASSET_TYPE: iam.googleapis.com/ServiceAccountKey
# TAGS: Security, Management, IAM, Service Account Key
########################################################################

package google.iam.serviceAccountKeyExpire

import data.validator.google.lib as lib
import data.validator.google.lib.parameters as gparam
import future.keywords

asset := input.asset

params := lib.get_default(gparam.global_parameters, "iam", {})

deny[{"msg": message, "details": metadata}] if{

    valid_days := lib.get_default(params, "serviceAccountKeyExpireDays", 90)

    message:= is_valid_expiration(asset,valid_days)
    message
  	metadata:= {"name": asset.name}

}

# This helper function checks if key validation time is within defined parameters.
is_valid_expiration(asset,valid_days) = output if{
  validAfterTime := parse_utc_timestamp_to_nanoseconds(asset.resource.data.validAfterTime)
  validBeforeTime := time_parse_default(asset.resource.data.validBeforeTime,8033799171000000000)
  time.add_date(validAfterTime, 0, 0, valid_days) < validBeforeTime
  output := sprintf("Violation %v days rotation for Service Account Key. Current config { validAfterTime: %v , validBeforeTime: %v}", [valid_days,asset.resource.data.validAfterTime,asset.resource.data.validBeforeTime])
}

#This Helper function provides default value for time parser functions that may be limited by int64
time_parse_default(resource,_default) = output if{
 a:= parse_utc_timestamp_to_nanoseconds(resource)
 a!= ""
 output:=a
}
else = output if{
 output:=_default
}

#this helper function converts UTC timestamp into ns
parse_utc_timestamp_to_nanoseconds(ts) = result if{
  time_obj := {
	"year": to_number(trim_left(split(split(ts, " ")[0], "-")[0],"0")),
    "month": to_number(trim_left(split(split(ts, " ")[0], "-")[1],"0")),
    "day":   to_number(trim_left(split(split(ts, " ")[0], "-")[2],"0")),
    "hour":  to_number(trim_left(split(split(ts, " ")[1], ":")[0],"0")),
    "minute":to_number(trim_left(split(split(ts, " ")[1], ":")[1],"0")),
    "second":to_number(trim_left(split(split(ts, " ")[1], ":")[2],"0"))
    }

  # Get seconds since epoch
  seconds_since_epoch := get_seconds_since_epoch(time_obj)

  # Convert to nanoseconds
  result := seconds_since_epoch * 1000000000
  }

get_seconds_since_epoch(time_obj) = total_seconds if{
    # Simplified calculation, adjustments needed for leap years, daylight saving time, etc.
    years_since_epoch := time_obj["year"] - 1970
    leap:= floor(years_since_epoch/4)
    days_second = (month_calc(time_obj["month"],time_obj["year"]) + time_obj["day"]-1)*86400
    total_seconds_y:=((years_since_epoch-leap)*31536000+leap*31622400)
    hr_seconds:=time_obj["hour"]*60*60+time_obj["minute"]*60+time_obj["second"]
    total_seconds:=total_seconds_y+days_second +hr_seconds
}

# Helper function to add additional day based on leap year and month
is_leap_year(month,year) =t if{
    year % 4 == 0
    month>2
    t:=1
} else =0

month_calc(month,year) =output if{
days_in_months := [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
output := sum([x|x:=days_in_months[k];k<month-1])+ is_leap_year(month,year)
}
