//{{ Liquid }}
//Copyright (C) {{ 2019 }}  {{ Blockstream }}

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

//! # HSM update tool
//!
//! Sends a file (e.g. rpm package) to a connected hsm via parallel_port for processing (e.g. installation).
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

use functionary::hsm::SecurityModule;
use std::borrow::Borrow;

pub struct TransferContext {
    sequenced_id: u32,
    _security_module: Box<dyn SecurityModule>,
}

impl TransferContext {
    pub fn new(security_module: Box<dyn SecurityModule>) -> TransferContext {
        TransferContext {
            sequenced_id: rand::random::<u32>(),
            _security_module: security_module,
        }
    }

    pub fn get_id(&self) -> u32 {
        self.sequenced_id
    }

    pub fn _set_id(&mut self, value: u32) {
        self.sequenced_id = value;
    }

    pub fn _get_previous_id(&self) -> u32 {
        let mut result = self.sequenced_id.wrapping_sub(1);
        if result == 0 {
            result = u32::max_value();
        }
        result
    }

    pub fn inc_id(&mut self) {
        self.sequenced_id = self.sequenced_id.wrapping_add(1);
        // 0 is considered to be uninitialized
        if self.sequenced_id == 0 {
            self.sequenced_id = self.sequenced_id.wrapping_add(1);
        }
    }

    pub fn security_module(&self) -> &dyn SecurityModule {
       self._security_module.borrow()
    }
}

#[cfg(test)]
pub mod tests {
    use functionary::hsm::LiquidHsm;
    use functionary_common::hsm::Error;
    use transfer_context::TransferContext;

    #[test]
    fn test_new() -> Result<(), Error> {
        let socket_path = String::from("/foo/bar");
        let sm = Box::new(LiquidHsm::new(socket_path));
        let context1 = TransferContext::new(sm);
        let socket_path2 = String::from("/foo/bar");
        let sm2 = Box::new(LiquidHsm::new(socket_path2));
        let context2 = TransferContext::new(sm2);
        assert_ne!(context1.sequenced_id, context2.sequenced_id);
        Ok(())
    }

    #[test]
    fn test_get_security_module() -> Result<(), Error> {
        let socket_path = String::from("/foo/bar");
        let liquid_sm = LiquidHsm::new(socket_path);
        let sm = Box::new(liquid_sm);
        let context = TransferContext::new(sm);
        let _security_module = context.security_module();
        Ok(())
    }

    #[test]
    fn test_get() -> Result<(), Error> {
        let socket_path = String::from("/foo/bar");
        let sm = Box::new(LiquidHsm::new(socket_path));
        let mut context = TransferContext::new(sm);
        context._set_id(42);
        assert_eq!(context.get_id(), 42);
        context._set_id(0);
        assert_eq!(context.get_id(), 0);
        Ok(())
    }

    #[test]
    fn test_inc_id() -> Result<(), Error> {
        let socket_path = String::from("/foo/bar");
        let sm = Box::new(LiquidHsm::new(socket_path));
        let mut context = TransferContext::new(sm);
        context._set_id(42);
        context.inc_id();
        assert_eq!(context.get_id(), 43);
        context._set_id(u32::max_value());
        context.inc_id();
        assert_eq!(context.get_id(), 1);
        context._set_id(0);
        context.inc_id();
        assert_eq!(context.get_id(), 1);
        Ok(())
    }

    #[test]
    fn test_previous_id() -> Result<(), Error> {
        let socket_path = String::from("/foo/bar");
        let sm = Box::new(LiquidHsm::new(socket_path));
        let mut context = TransferContext::new(sm);
        context._set_id(42);
        assert_eq!(context._get_previous_id(), 41);
        context._set_id(1);
        assert_eq!(context._get_previous_id(), u32::max_value());
        context._set_id(0);
        assert_eq!(context._get_previous_id(), u32::max_value());
        Ok(())
    }


}
