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


//! # I/O related logs
//!

/// Reading from a file failed
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ReadFailed<'a> {
    /// Path to the file
    pub filename: &'a str,
    /// Error that was encountered
    pub error: String,
}

/// Writing to a file failed
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct WriteFailed<'a> {
    /// Path to the file
    pub filename: &'a str,
    /// Error that was encountered
    pub error: String,
}

/// Creating a file failed
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct CreateFailed<'a> {
    /// Path to the file
    pub filename: &'a str,
    /// Error that was encountered
    pub error: String,
}

/// Renaming/moving a file failed
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct MoveFailed<'a> {
    /// Path to the original filename
    pub old_filename: &'a str,
    /// Path to the intended new filename
    pub new_filename: &'a str,
    /// Error that was encountered
    pub error: String,
}

