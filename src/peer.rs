use crate::common::*;
use crate::database;
use hbb_common::{
    bytes::Bytes,
    log,
    rendezvous_proto::*,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
    pub(crate) alias: String,          // Fatima Desk
    pub(crate) pending_id: String,     // Fatima Desk: ID assigned in the Console
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
            alias: String::new(),
            pending_id: String::new(),
        }
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
}

impl PeerMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = std::env::var("DB_URL").unwrap_or({
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(pm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
    ) -> register_pk_response::Result {
        log::info!("update_pk {} {:?} {:?} {:?}", id, addr, uuid, pk);
        let (info_str, guid) = {
            let mut w = peer.write().await;
            w.socket_addr = addr;
            w.uuid = uuid.clone();
            w.pk = pk.clone();
            w.last_reg_time = Instant::now();
            w.info.ip = ip;
            (
                serde_json::to_string(&w.info).unwrap_or_default(),
                w.guid.clone(),
            )
        };
        if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Err(err) => {
                    log::error!("db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
                Ok(guid) => {
                    peer.write().await.guid = guid;
                }
            }
        } else {
            if let Err(err) = self.db.update_pk(&guid, &id, &pk, &info_str).await {
                log::error!("db.update_pk failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            log::info!("pk updated instead of insert");
        }
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, id: &str) -> Option<LockPeer> {
        let p = self.map.read().await.get(id).cloned();
        if p.is_some() {
            return p;
        } else if let Ok(Some(v)) = self.db.get_peer(id).await {
            let alias = self.db.get_alias(&v.guid).await.ok().flatten().unwrap_or_default();
            let pending_id = self.db.get_pending_id(&v.guid).await.ok().flatten().unwrap_or_default();
            let peer = Peer {
                alias,
                pending_id,
                guid: v.guid,
                uuid: v.uuid.into(),
                pk: v.pk.into(),
                // user: v.user,
                info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
                // disabled: v.status == Some(0),
                ..Default::default()
            };
            let peer = Arc::new(RwLock::new(peer));
            self.map.write().await.insert(id.to_owned(), peer.clone());
            return Some(peer);
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        if let Some(p) = self.get(id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return p.clone();
        }
        let tmp = LockPeer::default();
        w.insert(id.to_owned(), tmp.clone());
        tmp
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }

    /// Fatima Desk: move a registered device from `old_id` to `new_id`
    /// (the client's "Change ID"). Only the device that owns `old_id` may do
    /// this: the request must carry its UUID and come from the IP it last
    /// registered from. The device keeps its key, so its next registration
    /// under `new_id` is accepted as the same device.
    pub(crate) async fn change_id(
        &self,
        old_id: &str,
        new_id: &str,
        uuid: &[u8],
        ip: &str,
    ) -> register_pk_response::Result {
        use register_pk_response::Result::*;
        let norm = |s: &str| s.trim_start_matches("::ffff:").to_owned();

        let Some(peer) = self.get(old_id).await else {
            log::warn!("change_id: {} -> {}: old id not registered", old_id, new_id);
            return UUID_MISMATCH;
        };
        let guid = {
            let p = peer.read().await;
            if p.guid.is_empty() || p.uuid.as_ref() != uuid {
                log::warn!("change_id: {} -> {}: uuid mismatch", old_id, new_id);
                return UUID_MISMATCH;
            }
            if !p.info.ip.is_empty() && norm(&p.info.ip) != norm(ip) {
                log::warn!(
                    "change_id: {} -> {}: request from {} but device is at {}",
                    old_id,
                    new_id,
                    ip,
                    p.info.ip
                );
                return UUID_MISMATCH;
            }
            p.guid.clone()
        };

        // Loads the target from the database into memory if it exists there.
        let _ = self.get(new_id).await;

        let mut map = self.map.write().await;
        if let Some(target) = map.get(new_id) {
            let t = target.read().await;
            if !t.uuid.is_empty() && t.uuid.as_ref() != uuid {
                return ID_EXISTS;
            }
            // The same device used this ID before: drop that old record so
            // the rename can take the ID back.
            if !t.guid.is_empty() && t.guid != guid {
                if let Err(err) = self.db.delete_peer(&t.guid).await {
                    log::error!("change_id: delete stale {} failed: {}", new_id, err);
                    return SERVER_ERROR;
                }
            }
        }
        if let Err(err) = self.db.rename_peer(&guid, new_id).await {
            log::error!("change_id: {} -> {} failed: {}", old_id, new_id, err);
            return SERVER_ERROR;
        }
        map.remove(old_id);
        map.insert(new_id.to_owned(), peer);
        log::info!("change_id: {} -> {} (ip {})", old_id, new_id, ip);
        OK
    }

    /// Fatima Desk: the device's own "Set alias". Same ownership rule as
    /// `change_id`: its UUID, from the IP it last registered from.
    pub(crate) async fn set_alias_owned(
        &self,
        id: &str,
        uuid: &[u8],
        ip: &str,
        alias: &str,
    ) -> fd_set_alias_response::Result {
        use fd_set_alias_response::Result::*;
        let norm = |s: &str| s.trim_start_matches("::ffff:").to_owned();
        let Some(peer) = self.get(id).await else {
            return UUID_MISMATCH;
        };
        {
            let p = peer.read().await;
            if p.guid.is_empty() || p.uuid.as_ref() != uuid {
                log::warn!("set_alias: {}: uuid mismatch", id);
                return UUID_MISMATCH;
            }
            if !p.info.ip.is_empty() && norm(&p.info.ip) != norm(ip) {
                log::warn!("set_alias: {}: request from {} but device is at {}", id, ip, p.info.ip);
                return UUID_MISMATCH;
            }
        }
        self.set_alias(id, &peer, alias).await
    }

    /// Fatima Desk: set (or, with an empty `alias`, remove) the alias of the
    /// device `id`, without an ownership check (the Console's admin command).
    pub(crate) async fn set_alias(
        &self,
        id: &str,
        peer: &LockPeer,
        alias: &str,
    ) -> fd_set_alias_response::Result {
        use fd_set_alias_response::Result::*;
        let guid = peer.read().await.guid.clone();
        if guid.is_empty() {
            return UUID_MISMATCH;
        }
        if alias.is_empty() {
            if let Err(err) = self.db.delete_alias(&guid).await {
                log::error!("set_alias: {}: {}", id, err);
                return SERVER_ERROR;
            }
        } else {
            match self.db.alias_or_id_owner(alias).await {
                Ok(Some(owner)) if owner != guid => return ALIAS_EXISTS,
                Ok(_) => {}
                Err(err) => {
                    log::error!("set_alias: {}: {}", id, err);
                    return SERVER_ERROR;
                }
            }
            if let Err(err) = self.db.set_alias(&guid, alias).await {
                log::error!("set_alias: {} -> {}: {}", id, alias, err);
                return ALIAS_EXISTS;
            }
        }
        peer.write().await.alias = alias.to_owned();
        log::info!("set_alias: {} -> {:?}", id, alias);
        OK
    }

    /// Fatima Desk: remember (or, with an empty `new_id`, drop) the ID the
    /// admin assigned to this device, in the database and in memory.
    pub(crate) async fn set_pending_id(&self, peer: &LockPeer, new_id: &str) -> ResultType<()> {
        let guid = peer.read().await.guid.clone();
        if new_id.is_empty() {
            self.db.delete_pending_id(&guid).await?;
        } else {
            self.db.set_pending_id(&guid, new_id).await?;
        }
        peer.write().await.pending_id = new_id.to_owned();
        Ok(())
    }

    pub(crate) async fn resolve_alias(&self, alias: &str) -> String {
        self.db.resolve_alias(alias).await.ok().flatten().unwrap_or_default()
    }
}
