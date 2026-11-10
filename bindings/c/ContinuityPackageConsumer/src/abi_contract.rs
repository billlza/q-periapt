// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Compiled native side of the independent C declaration/layout comparison.

macro_rules! abi_record {
    ($name:literal, $record:ident, { $($field:ident: $kind:ty,)+ }) => {{
        // A layout match alone cannot detect a changed signedness, pointee or
        // pointer mutability. These coercions also check each actual field type.
        $(let _: fn(&$record) -> &$kind = |record| &record.$field;)+
        // Exhaustiveness also detects an added field that fits existing padding.
        let _: fn(&$record) = |record| {
            let $record { $($field: _,)+ } = record;
        };
        println!("QPC_ABI_NATIVE {} {}", $name,
                 std::any::type_name::<$record>().replace(' ', ""));
        print!("QPC_ABI {} {} {}", $name, std::mem::size_of::<$record>(),
               std::mem::align_of::<$record>());
        $(print!(" {}:{}:{}:{}", stringify!($field),
                 std::mem::offset_of!($record, $field), std::mem::size_of::<$kind>(),
                 std::any::type_name::<$kind>().replace(' ', ""));)+
        println!();
    }};
}

macro_rules! abi_signature {
    ($name:ident, ($($kind:ty),* $(,)?)) => {{
        print!("QPC_ABI_FUNCTION {} i32", stringify!($name));
        $(print!(" {}", std::any::type_name::<$kind>().replace(' ', ""));)*
        println!();
    }};
}

macro_rules! abi_function {
    ($name:ident, ($($kind:ty),* $(,)?)) => {{
        let _: unsafe extern "C" fn($($kind),*) -> i32 = $name;
        abi_signature!($name, ($($kind),*));
    }};
}

#[test]
fn declared_c_types_match_native_owners() {
    use std::{
        ffi::c_void,
        mem::{align_of, size_of},
    };
    // The public callback is nullable at admission and non-null after checking.
    let _: fn(
        super::server::Commit,
    )
        -> unsafe extern "C" fn(*mut c_void, *const u8, *const u8, *const u8, usize) -> i32 =
        |callback| callback;
    println!(
        "QPC_ABI target {} {}",
        size_of::<usize>(),
        align_of::<usize>()
    );
    println!(
        "QPC_ABI_NATIVE qpc_commit_v1 {}",
        std::any::type_name::<Option<super::server::Commit>>().replace(' ', "")
    );
    abi_signature!(
        qpc_commit_v1,
        (*mut c_void, *const u8, *const u8, *const u8, usize)
    );
    println!(
        "QPC_ABI qpc_commit_v1 {} {}",
        size_of::<Option<super::server::Commit>>(),
        align_of::<Option<super::server::Commit>>()
    );
    super::verify_c_abi();
}
