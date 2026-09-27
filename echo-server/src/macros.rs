#[allow(unused)] // Needed for documentation
use sqlx::{FromRow, postgres::PgRow};

/// Fetch exactly one row from the database using
/// a given query, returning it as a [`PgRow`].
#[macro_export]
macro_rules! fetch_one {
    ($conn:expr, $s:expr, $($v:expr),+) => {{
        let mut query = sqlx::query($s);

        $(
            query = query.bind($v);
        )+

        query
            .fetch_one($conn)
            .await
            .context($crate::error::RouteError::Database)?
    }};
}

/// Fetch exactly one row from the database using a given
/// query, but returning it as another type, as long as
/// that type implements [`FromRow`].
#[macro_export]
macro_rules! fetch_one_as {
    ($conn:expr, $s:expr, $($v:expr),+) => {{
        let mut query = sqlx::query_as($s);

        $(
            query = query.bind($v);
        )+

        query
            .fetch_one($conn)
            .await
            .context($crate::error::RouteError::Database)?
    }};
}

/// Fetch exactly one row from the database and extract the
/// value of the first column of that returned row.
#[macro_export]
macro_rules! fetch_one_scalar {
    ($conn:expr, $s:expr, $($v:expr),+) => {{
        let mut query = sqlx::query_scalar($s);

        $(
            query = query.bind($v);
        )+

        query
            .fetch_one($conn)
            .await
            .context($crate::error::RouteError::Database)?
    }};
}

/// Try to fetch one row from the database using a given query.
#[macro_export]
macro_rules! fetch_opt {
    ($conn:expr, $s:expr, $($v:expr),+) => {{
        let mut query = sqlx::query($s);

        $(
            query = query.bind($v);
        )+

        query
            .fetch_optional($conn)
            .await
            .context($crate::error::RouteError::Database)?
    }};
}

/// Try to fetch one row from the database
/// using a given query, and if it exists,
/// convert it to another type that
/// implements [`FromRow`].
#[macro_export]
macro_rules! fetch_opt_as {
    ($conn:expr, $s:expr, $($v:expr),+) => {{
        let mut query = sqlx::query_as($s);

        $(
            query = query.bind($v);
        )+

        query
            .fetch_optional($conn)
            .await
            .context($crate::error::RouteError::Database)?
    }};
}

/// Try to fetch one row from the database with a
/// given query, and if it exists, extract the
/// value from the first column.
#[macro_export]
macro_rules! fetch_opt_scalar {
    ($conn:expr, $s:expr, $($v:expr),+) => {{
        let mut query = sqlx::query_scalar($s);

        $(
            query = query.bind($v);
        )+

        query
            .fetch_optional($conn)
            .await
            .context($crate::error::RouteError::Database)?
    }};
}

/// Fetch all rows from the database that match
/// a given query.
#[macro_export]
macro_rules! fetch_all {
    ($conn:expr, $s:expr, $($v:expr),+) => {{
        let mut query = sqlx::query($s);

        $(
            query = query.bind($v);
        )+

        query
            .fetch_all($conn)
            .await
            .context($crate::error::RouteError::Database)?
    }};
}

/// Fetch all rows from the database that match
/// a given query, converting each row to another
/// type that implements [`FromRow`].
#[macro_export]
macro_rules! fetch_all_as {
    ($conn:expr, $s:expr, $($v:expr),+) => {{
        let mut query = sqlx::query_as($s);

        $(
            query = query.bind($v);
        )+

        query
            .fetch_all($conn)
            .await
            .context($crate::error::RouteError::Database)?
    }};
}

/// Fetch all rows form the database that match a given query,
/// extracting the value from the first column of each row.
#[macro_export]
macro_rules! fetch_all_scalar {
    ($conn:expr, $s:expr, $($v:expr),+) => {{
        let mut query = sqlx::query_scalar($s);

        $(
            query = query.bind($v);
        )+

        query
            .fetch_all($conn)
            .await
            .context($crate::error::RouteError::Database)?
    }};
}

/// Execute a single query, typically one that isn't expected
/// to return something.
///
/// This is preferred for `INSERT` or `UPDATE` statements for
/// example.
#[macro_export]
macro_rules! execute {
    ($conn:expr, $s:expr, $($v:expr),+) => {{
        let mut query = sqlx::query($s);

        $(
            query = query.bind($v);
        )+

        query
            .execute($conn)
            .await
            .context($crate::error::RouteError::Database)?
    }};
}
