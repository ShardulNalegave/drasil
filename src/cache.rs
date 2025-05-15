
pub mod redis;

pub type Cache = Box<dyn CacheProvider>;

pub trait CacheProvider {
    fn store();
    fn get();
    fn delete();
}