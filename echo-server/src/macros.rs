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

#[macro_export]
macro_rules! ok {
    ($value:expr) => {{
        Ok::<_, ()>($value)
    }};
}
