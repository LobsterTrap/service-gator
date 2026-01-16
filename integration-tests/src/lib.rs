//! Shared library code for integration tests
//!
//! This module contains test registration utilities shared between
//! the main test binary and helper binaries.

// Unfortunately needed here to work with linkme
#![allow(unsafe_code)]

/// A test function that returns a Result
pub type TestFn = fn() -> eyre::Result<()>;

/// Metadata for a registered integration test
#[derive(Debug)]
pub struct IntegrationTest {
    /// Name of the integration test
    pub name: &'static str,
    /// Test function to execute
    pub f: TestFn,
}

impl IntegrationTest {
    /// Create a new integration test with the given name and function
    pub const fn new(name: &'static str, f: TestFn) -> Self {
        Self { name, f }
    }
}

/// Distributed slice holding all registered integration tests
#[linkme::distributed_slice]
pub static INTEGRATION_TESTS: [IntegrationTest];

/// Register an integration test with less boilerplate.
///
/// This macro generates the static registration for an integration test function.
///
/// # Examples
///
/// ```ignore
/// fn test_basic_functionality() -> Result<()> {
///     // test code here
///     Ok(())
/// }
/// integration_test!(test_basic_functionality);
/// ```
#[macro_export]
macro_rules! integration_test {
    ($fn_name:ident) => {
        ::paste::paste! {
            #[::linkme::distributed_slice($crate::INTEGRATION_TESTS)]
            static [<$fn_name:upper>]: $crate::IntegrationTest =
                $crate::IntegrationTest::new(stringify!($fn_name), $fn_name);
        }
    };
}
