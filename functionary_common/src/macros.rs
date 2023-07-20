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




/// Macro to shorten the case where you want to unwrap something
/// or run some code otherwise.
#[macro_export]
macro_rules! unwrap_opt_or {
    ($maybe:expr, $else:tt) => {
        if let Some(v) = $maybe {
            v
        } else {
            $else
        }
    }
}

/// Macro to shorten the case where you want to unwrap something
/// or run some code otherwise.
#[macro_export]
macro_rules! unwrap_res_or {
    ($maybe:expr, $else:tt) => {
        if let Ok(v) = $maybe {
            v
        } else {
            $else
        }
    }
}

#[cfg(test)]
mod test {
    fn opt_return_false_on_else(opt: Option<usize>) -> bool {
        let _x: usize = unwrap_opt_or!(opt, {
            return false;
        });
        return true;
    }

    #[test]
    fn test_unwrap_opt_or() {
        let opt = Some(5);
        assert_eq!(unwrap_opt_or!(opt, { panic!("foo"); }), 5);

        assert!(opt_return_false_on_else(Some(5)));
        assert!(!opt_return_false_on_else(None));
    }

    #[test]
    #[should_panic(expected = "bar")]
    fn test_unwrap_opt_or_fail() {
        let opt = Option::<bool>::None;
        let _x = unwrap_opt_or!(opt, { panic!("bar"); });
    }

    fn res_return_false_on_else(opt: Result<usize, ()>) -> bool {
        let _x: usize = unwrap_res_or!(opt, {
            return false;
        });
        return true;
    }

    #[test]
    fn test_unwrap_res_or() {
        let res = Result::<usize, ()>::Ok(5);
        assert_eq!(unwrap_res_or!(res, { panic!("foo"); }), 5);

        assert!(res_return_false_on_else(Ok(5)));
        assert!(!res_return_false_on_else(Err(())));
    }

    #[test]
    #[should_panic(expected = "bar")]
    fn test_unwrap_res_or_fail() {
        let res = Result::<usize, ()>::Err(());
        let _x = unwrap_res_or!(res, { panic!("bar"); });
    }
}
