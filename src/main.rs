use std::{fmt::Display, str::FromStr};

use pgtemp::PgTempDB;
use rootcause::Result;
use sqlx::{Decode, Encode, postgres::{PgArgumentBuffer, PgConnectOptions, PgPoolOptions, Postgres}};

#[derive(Debug, PartialEq, sqlx::Type)]
#[sqlx(type_name = "\"Activity\"")]
enum Activity {
    Online,
    Idle,
    DoNotDisturb,
    Offline
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct AssetID([u8; 32]);

impl Display for AssetID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Encode<'_, Postgres> for AssetID {
    fn encode_by_ref(
        &self,
        buf: &mut PgArgumentBuffer
    ) -> std::result::Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        buf.extend_from_slice(hex::encode(self.0).as_bytes());

        Ok(sqlx::encode::IsNull::No)
    }
}

impl Decode<'_, Postgres> for AssetID {
    fn decode(
        value: <Postgres as sqlx::Database>::ValueRef<'_>
    ) -> std::result::Result<Self, sqlx::error::BoxDynError> {
        let raw = value.as_bytes()?;

        let bytes = hex::decode(raw)?;

        match bytes.try_into() {
            Ok(buf) => Ok(Self(buf)),
            Err(_) => Err("invalid byte length".into())
        }
    }
}

impl sqlx::Type<Postgres> for AssetID {
    fn type_info() -> <Postgres as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<Postgres>>::type_info()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let temp = PgTempDB::from_builder(
        PgTempDB::builder()
            .with_bin_path("/usr/lib/postgresql/17/bin")
    );

    let options = PgConnectOptions::from_str(&temp.connection_uri())?
        .statement_cache_capacity(0);

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    {
        let schema = include_str!("../SCHEMA.sql");

        sqlx::raw_sql(schema)
            .execute(&pool)
            .await?;
    }

    let name = "james.hanley";
    let display_name = "James Hanley";

    let avatar = AssetID(rand::random());
    let activity = Activity::Online;

    {
        let stmt = "
            INSERT INTO users (
                id,
                name,
                display_name,
                avatar,
                activity
            ) VALUES ($1, $2, $3, $4, $5)
        ";

        sqlx::query(stmt)
            .bind(1i64)
            .bind(name)
            .bind(display_name)
            .bind(avatar)
            .bind(&activity)
            .execute(&pool)
            .await?;
    }

    let stmt = "SELECT name, display_name, avatar, activity FROM users WHERE id = $1";

    let (name2, display_name2, avatar2, activity2): (
        String,
        String,
        AssetID,
        Activity
    ) = sqlx::query_as(stmt)
        .bind(1i64)
        .fetch_one(&pool)
        .await?;

    assert_eq!(name, name2, "names differed: {name} vs {name2}");
    assert_eq!(display_name, display_name2, "display names differed: {display_name} vs {display_name2}");
    assert_eq!(avatar, avatar2, "names differed: {avatar} vs {avatar2}");
    assert_eq!(activity, activity2, "names differed: {activity:?} vs {activity2:?}");

    println!("all assertions passed!");

    Ok(())
}
