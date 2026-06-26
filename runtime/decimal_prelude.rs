#[cfg(feature = "decimal")]
use rust_decimal::Decimal;
#[cfg(feature = "decimal")]
trait IntoDec { fn into_dec(&self) -> Decimal; }
#[cfg(feature = "decimal")]
impl IntoDec for str { fn into_dec(&self) -> Decimal { std::str::FromStr::from_str(self).unwrap_or_default() } }
#[cfg(feature = "decimal")]
impl IntoDec for String { fn into_dec(&self) -> Decimal { std::str::FromStr::from_str(self.as_str()).unwrap_or_default() } }
#[cfg(feature = "decimal")]
impl IntoDec for i64 { fn into_dec(&self) -> Decimal { Decimal::from(*self) } }
#[cfg(feature = "decimal")]
impl IntoDec for i32 { fn into_dec(&self) -> Decimal { Decimal::from(*self) } }
#[cfg(feature = "decimal")]
fn __dec_add<A: IntoDec + ?Sized, B: IntoDec + ?Sized>(a: &A, b: &B) -> String { (a.into_dec() + b.into_dec()).to_string() }
#[cfg(feature = "decimal")]
fn __dec_sub<A: IntoDec + ?Sized, B: IntoDec + ?Sized>(a: &A, b: &B) -> String { (a.into_dec() - b.into_dec()).to_string() }
#[cfg(feature = "decimal")]
fn __dec_mul<A: IntoDec + ?Sized, B: IntoDec + ?Sized>(a: &A, b: &B) -> String { (a.into_dec() * b.into_dec()).to_string() }
#[cfg(feature = "decimal")]
fn __dec_lt<A: IntoDec + ?Sized, B: IntoDec + ?Sized>(a: &A, b: &B) -> bool { a.into_dec() < b.into_dec() }
#[cfg(feature = "decimal")]
fn __dec_gt<A: IntoDec + ?Sized, B: IntoDec + ?Sized>(a: &A, b: &B) -> bool { a.into_dec() > b.into_dec() }
#[cfg(feature = "decimal")]
fn __dec_le<A: IntoDec + ?Sized, B: IntoDec + ?Sized>(a: &A, b: &B) -> bool { a.into_dec() <= b.into_dec() }
#[cfg(feature = "decimal")]
fn __dec_ge<A: IntoDec + ?Sized, B: IntoDec + ?Sized>(a: &A, b: &B) -> bool { a.into_dec() >= b.into_dec() }
