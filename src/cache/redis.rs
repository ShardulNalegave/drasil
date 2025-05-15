
// ===== Imports =====
use anyhow::Result;
use crate::cache::CacheProvider;
// ===================

pub struct RedisCache {
    client: redis::Client,
    conn: redis::Connection,
}

impl RedisCache {
    pub fn new() -> Result<Self> {
        let client = redis::Client::open("redis://127.0.0.1/")?;
        let conn = client.get_connection()?;

        Ok(Self { client, conn })
    }
}

impl CacheProvider for RedisCache {
    fn store() {
        unimplemented!()
    }
    
    fn get() {
        unimplemented!()
    }
    
    fn delete() {
        unimplemented!()
    }
}