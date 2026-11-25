mod fixture;
#[cfg(feature = "http")]
mod limits;
#[cfg(feature = "http")]
mod mock_http;
mod path;
mod planner;
mod pulling;
mod pushing;
mod recovery;
#[cfg(feature = "http")]
mod s3_http;
mod send;
mod sessions;
mod sigv4;
mod store;
#[cfg(feature = "http")]
mod webdav_http;
mod xml;
