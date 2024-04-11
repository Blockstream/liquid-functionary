//{{ Liquid }}
//Copyright (C) {{ 2015,2016,2017,2018 }}  {{ Blockstream }}

//This program is free software: you can redistribute it and/or modify
//it under the terms of the GNU Affero General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU Affero General Public License for more details.

//You should have received a copy of the GNU Affero General Public License
//along with this program.  If not, see <http://www.gnu.org/licenses/>.


//! # HSM related logs
//!

use serde::{ser::Error, Serialize, Serializer};
use serde_json::value::RawValue;

/// Status of HSM component
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct HsmComponentStatus {
    pub component: String,
    /// Status returned from HSM query
    #[serde(serialize_with = "as_json_object")]
    pub status: String,
}

fn as_json_object<S>(v: &str, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let v: &RawValue = serde_json::from_str(v).map_err(|_| Error::custom("error parsing serialized json"))?;
    v.serialize(s)
}

/// Result of HSM component audit
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HsmAuditResult {
    pub component: String,
    // AuditMode (Data or TamperDetection)
    pub mode: String,
    pub discrepancy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correction: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_correction_discrepancy: Option<bool>,
}

/// Error during performance of HSM component audit
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct HsmAuditError {
    pub component: String,
    pub error: String,
}