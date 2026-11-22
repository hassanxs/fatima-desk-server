use async_trait::async_trait;
use hbb_common::{log, ResultType};
use sqlx::{
    sqlite::SqliteConnectOptions, ConnectOptions, Connection, Error as SqlxError, SqliteConnection,
};
use std::{ops::DerefMut, str::FromStr};
//use sqlx::postgres::PgPoolOptions;
//use sqlx::mysql::MySqlPoolOptions;

type Pool = deadpool::managed::Pool<DbPool>;

pub struct DbPool {
    url: String,
}

#[async_trait]
impl deadpool::managed::Manager for DbPool {
    type Type = SqliteConnection;
    type Error = SqlxError;
    async fn create(&self) -> Result<SqliteConnection, SqlxError> {
        let mut opt = SqliteConnectOptions::from_str(&self.url).unwrap();
        opt.log_statements(log::LevelFilter::Debug);
        SqliteConnection::connect_with(&opt).await
    }
    async fn recycle(
        &self,
        obj: &mut SqliteConnection,
    ) -> deadpool::managed::RecycleResult<SqlxError> {
        Ok(obj.ping().await?)
    }
}

#[derive(Clone)]
pub struct Database {
    pool: Pool,
}

#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let n: usize = std::env::var("MAX_DATABASE_CONNECTIONS")
            .unwrap_or_else(|_| "1".to_owned())
            .parse()
            .unwrap_or(1);
        log::debug!("MAX_DATABASE_CONNECTIONS={}", n);
        let pool = Pool::new(
            DbPool {
                url: url.to_owned(),
            },
            n,
        );
        let _ = pool.get().await?; // test
        let db = Database { pool };
        db.create_tables().await?;
        db.create_fd_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        sqlx::query!(
            "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);
        "
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        Ok(sqlx::query_as!(
            Peer,
            "select guid, id, uuid, pk, user, status, info from peer where id = ?",
            id
        )
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        sqlx::query!(
            "insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)",
            guid,
            id,
            uuid,
            pk,
            info
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        sqlx::query!(
            "update peer set id=?, pk=?, info=? where guid=?",
            id,
            pk,
            info,
            guid
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    // Fatima Desk (custom IDs). Runtime-checked queries, so the compile-time
    // sqlx schema check is unchanged.
    pub async fn rename_peer(&self, guid: &[u8], id: &str) -> ResultType<()> {
        sqlx::query("update peer set id = ? where guid = ?")
            .bind(id)
            .bind(guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn delete_peer(&self, guid: &[u8]) -> ResultType<()> {
        sqlx::query("delete from peer where guid = ?")
            .bind(guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        sqlx::query("delete from fd_alias where guid = ?")
            .bind(guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        sqlx::query("delete from fd_pending_id where guid = ?")
            .bind(guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    // Fatima Desk aliases: one per device, keyed by the device's guid so the
    // alias stays with the device when its numeric ID changes. Unique without
    // regard to case.
    async fn create_fd_tables(&self) -> ResultType<()> {
        sqlx::query(
            "create table if not exists fd_alias (
                guid blob primary key not null,
                alias varchar(32) not null
            ) without rowid",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        sqlx::query("create unique index if not exists index_fd_alias_lower on fd_alias (lower(alias))")
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        // IDs assigned in the Console, waiting for the device to apply them.
        sqlx::query(
            "create table if not exists fd_pending_id (
                guid blob primary key not null,
                new_id varchar(100) not null unique
            ) without rowid",
        )
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn get_pending_id(&self, guid: &[u8]) -> ResultType<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("select new_id from fd_pending_id where guid = ?")
            .bind(guid)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?;
        Ok(row.map(|r| r.0))
    }

    /// guid of the device that `new_id` is already waiting for.
    pub async fn pending_id_owner(&self, new_id: &str) -> ResultType<Option<Vec<u8>>> {
        let row: Option<(Vec<u8>,)> = sqlx::query_as("select guid from fd_pending_id where new_id = ?")
            .bind(new_id)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?;
        Ok(row.map(|r| r.0))
    }

    pub async fn set_pending_id(&self, guid: &[u8], new_id: &str) -> ResultType<()> {
        sqlx::query(
            "insert into fd_pending_id (guid, new_id) values (?, ?)
             on conflict (guid) do update set new_id = excluded.new_id",
        )
        .bind(guid)
        .bind(new_id)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn delete_pending_id(&self, guid: &[u8]) -> ResultType<()> {
        sqlx::query("delete from fd_pending_id where guid = ?")
            .bind(guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// (current ID, assigned ID) of every assignment not applied yet.
    pub async fn list_pending_ids(&self) -> ResultType<Vec<(String, String)>> {
        Ok(sqlx::query_as(
            "select peer.id, fd_pending_id.new_id from fd_pending_id
             join peer on peer.guid = fd_pending_id.guid order by peer.id",
        )
        .fetch_all(self.pool.get().await?.deref_mut())
        .await?)
    }

    pub async fn get_alias(&self, guid: &[u8]) -> ResultType<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("select alias from fd_alias where guid = ?")
            .bind(guid)
            .fetch_optional(self.pool.get().await?.deref_mut())
            .await?;
        Ok(row.map(|r| r.0))
    }

    /// guid of the device that has `alias` as its alias, or `alias` as its ID.
    pub async fn alias_or_id_owner(&self, alias: &str) -> ResultType<Option<Vec<u8>>> {
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "select guid from fd_alias where lower(alias) = lower(?1)
             union all
             select guid from peer where lower(id) = lower(?1)
             limit 1",
        )
        .bind(alias)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row.map(|r| r.0))
    }

    pub async fn set_alias(&self, guid: &[u8], alias: &str) -> ResultType<()> {
        sqlx::query(
            "insert into fd_alias (guid, alias) values (?, ?)
             on conflict (guid) do update set alias = excluded.alias",
        )
        .bind(guid)
        .bind(alias)
        .execute(self.pool.get().await?.deref_mut())
        .await?;
        Ok(())
    }

    pub async fn delete_alias(&self, guid: &[u8]) -> ResultType<()> {
        sqlx::query("delete from fd_alias where guid = ?")
            .bind(guid)
            .execute(self.pool.get().await?.deref_mut())
            .await?;
        Ok(())
    }

    /// The numeric ID of the device whose alias is `alias`.
    pub async fn resolve_alias(&self, alias: &str) -> ResultType<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "select peer.id from fd_alias join peer on peer.guid = fd_alias.guid
             where lower(fd_alias.alias) = lower(?)",
        )
        .bind(alias)
        .fetch_optional(self.pool.get().await?.deref_mut())
        .await?;
        Ok(row.map(|r| r.0))
    }
}

#[cfg(test)]
mod fd_alias_tests {
    use hbb_common::tokio;

    #[tokio::test]
    async fn alias_roundtrip() {
        let path = std::env::temp_dir().join(format!("fd_alias_{}.sqlite3", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let db = super::Database::new(path.to_str().unwrap()).await.unwrap();
        let a = db.insert_peer("123456789", b"uuid-a", b"pk", "{}").await.unwrap();
        let b = db.insert_peer("987654321", b"uuid-b", b"pk", "{}").await.unwrap();

        db.set_alias(&a, "Office-PC").await.unwrap();
        assert_eq!(db.resolve_alias("office-pc").await.unwrap().as_deref(), Some("123456789"));
        assert_eq!(db.get_alias(&a).await.unwrap().as_deref(), Some("Office-PC"));
        // Taken by A, whatever the case; IDs count as taken too.
        assert_eq!(db.alias_or_id_owner("OFFICE-pc").await.unwrap(), Some(a.clone()));
        assert_eq!(db.alias_or_id_owner("987654321").await.unwrap(), Some(b.clone()));
        assert!(db.set_alias(&b, "office-PC").await.is_err());
        // Renaming the device keeps its alias.
        db.rename_peer(&a, "111222333").await.unwrap();
        assert_eq!(db.resolve_alias("Office-PC").await.unwrap().as_deref(), Some("111222333"));
        // Replace, then remove.
        db.set_alias(&a, "Home-PC").await.unwrap();
        assert_eq!(db.resolve_alias("Office-PC").await.unwrap(), None);
        db.delete_alias(&a).await.unwrap();
        assert_eq!(db.resolve_alias("Home-PC").await.unwrap(), None);

        // Pending assigned IDs survive in the database and follow the guid.
        db.set_pending_id(&a, "750000001").await.unwrap();
        assert_eq!(db.get_pending_id(&a).await.unwrap().as_deref(), Some("750000001"));
        assert_eq!(db.pending_id_owner("750000001").await.unwrap(), Some(a.clone()));
        assert!(db.set_pending_id(&b, "750000001").await.is_err());
        assert_eq!(
            db.list_pending_ids().await.unwrap(),
            vec![("111222333".to_owned(), "750000001".to_owned())]
        );
        db.delete_pending_id(&a).await.unwrap();
        assert!(db.list_pending_ids().await.unwrap().is_empty());
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod tests {
    use hbb_common::tokio;
    #[test]
    fn test_insert() {
        insert();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn insert() {
        let db = super::Database::new("test.sqlite3").await.unwrap();
        let mut jobs = vec![];
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                let empty_vec = Vec::new();
                cloned
                    .insert_peer(&id, &empty_vec, &empty_vec, "")
                    .await
                    .unwrap();
            });
            jobs.push(a);
        }
        for i in 0..10000 {
            let cloned = db.clone();
            let id = i.to_string();
            let a = tokio::spawn(async move {
                cloned.get_peer(&id).await.unwrap();
            });
            jobs.push(a);
        }
        hbb_common::futures::future::join_all(jobs).await;
    }
}
