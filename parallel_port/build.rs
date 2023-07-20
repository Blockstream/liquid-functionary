//{{ Liquid }}
//Copyright (C) {{ 2022 }}  {{ Blockstream }}

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

use anyhow;
use regex::Regex;
use std::fs::{read_to_string, OpenOptions};
use std::io::Write;

fn main_inner() -> Result<(), anyhow::Error> {
    // Read the Functionary version from the the cargo.toml in the functionary crate
    let version_toml = include_str!("../functionary/Cargo.toml");
    let regex = Regex::new("version = \"(.*?)\"")?;

    let version = match regex.captures(version_toml) {
        None => {
            panic!("Could not read version from the functionary crate");
        }
        Some(matches) => matches.get(1).expect("index 1 must exist").as_str(),
    };

    let orig_file = read_to_string("./src/constants.rs").expect("'constants.rs' must exist");
    let mut modified_file = "".to_string();
    for line in orig_file.lines() {
        if line.contains("FUNCTIONARY_VERSION") {
            modified_file.push_str(
                format!("pub const FUNCTIONARY_VERSION: &str = \"{}\";\n", version).as_str(),
            );
        } else {
            modified_file.push_str(line);
            modified_file.push_str("\n");
        }
    }

    if orig_file != modified_file {
        let mut file =
            OpenOptions::new().truncate(true).write(true).open("./src/constants.rs").unwrap();
        file.write(modified_file.as_bytes()).unwrap();

        // Tell Cargo that if the given files changes, to rerun this build script.
        println!("cargo:rerun-if-changed=../");
    }
    Ok(())
}

fn main() {
    if let Err(e) = main_inner() {
        panic!("Should be able to update constants.rs file: {}", e);
    }
}
