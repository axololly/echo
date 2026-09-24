use std::fmt::Display;

use bb8_postgres::PostgresConnectionManager;
use pgtemp::PgTempDB;
use postgres_types::{FromSql, ToSql, Type as PgType, to_sql_checked};
use rootcause::Result;
use tokio_postgres::{Config, NoTls, Row, ToStatement};

#[derive(Debug, Eq, FromSql, PartialEq, ToSql)]
enum Activity {
    Online,
    Idle,
    DoNotDisturb,
    Offline
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AssetID([u8; 32]);

impl Display for AssetID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<'a> FromSql<'a> for AssetID {
    fn accepts(ty: &PgType) -> bool {
        matches!(*ty, PgType::TEXT | PgType::VARCHAR)
    }

    fn from_sql(
        _: &PgType,
        raw: &'a [u8]
    ) -> std::result::Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        let bytes = hex::decode(raw)?;

        match bytes.try_into() {
            Ok(data) => Ok(Self(data)),
            Err(_) => Err("invalid byte length".into())
        }
    }
}

impl ToSql for AssetID {
    fn accepts(ty: &PgType) -> bool {
        ty.name() == "AssetID"
    }

    fn to_sql(
        &self,
        _: &PgType,
        out: &mut tokio_postgres::types::private::BytesMut
    ) -> std::result::Result<postgres_types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        out.extend_from_slice(hex::encode(self.0).as_bytes());

        Ok(postgres_types::IsNull::No)
    }

    to_sql_checked!();
}

#[tokio::main]
async fn main() -> Result<()> {
    let temp = PgTempDB::from_builder(
        PgTempDB::builder()
            .with_bin_path("/usr/lib/postgresql/17/bin")
    );

    let mut config = Config::new();

    config.options(temp.connection_string());

    let manager = PostgresConnectionManager::new(config, NoTls);

    let pool = bb8::Pool::builder().build(manager).await?;

    let schema = include_str!("../SCHEMA.sql");

    {
        let conn = pool.get().await?;

        conn.batch_execute(
            include_str!("../SCHEMA.sql")
        ).await?;
    }

    let name = "james.hanley";
    let display_name = "James Hanley";

    let avatar = AssetID(rand::random());
    let activity = Activity::Online;

    {
        let conn = pool.get().await?;

        let stmt = "
            INSERT INTO users (
                id,
                name,
                display_name,
                avatar,
                activity
            ) VALUES ($1, $2, $3, $4, $5)
        ";

        conn.execute(
            stmt,
            &[&1i64, &name, &display_name, &avatar, &activity]
        ).await?;
    }

    let conn = pool.get().await?;

    let row: Row = conn.query_one(
        "SELECT name, display_name, avatar, activity FROM users WHERE id = $1",
        &[&1i64]
    ).await?;

    let name2: String = row.get(0);
    let display_name2: String = row.get(1);
    let avatar2: AssetID = row.get(2);
    let activity2: Activity = row.get(3);

    assert_eq!(name, name2, "names differed: {name} vs {name2}");
    assert_eq!(display_name, display_name2, "display names differed: {display_name} vs {display_name2}");
    assert_eq!(avatar, avatar2, "names differed: {avatar} vs {avatar2}");
    assert_eq!(activity, activity2, "names differed: {activity:?} vs {activity2:?}");

    println!("all assertions passed!");

    Ok(())
}
