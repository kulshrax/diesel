extern crate url;

use std::ffi::{CStr, CString};
use self::url::{Host, Url};
use self::url::percent_encoding::percent_decode;

use result::{ConnectionError, ConnectionResult};

pub struct ConnectionOptions {
    host: Option<CString>,
    user: CString,
    password: Option<CString>,
    database: Option<CString>,
    port: Option<u16>,
    ssl_opts: Option<SslOptions>,
}

impl ConnectionOptions {
    pub fn parse(database_url: &str) -> ConnectionResult<Self> {
        let url = match Url::parse(database_url) {
            Ok(url) => url,
            Err(_) => return Err(connection_url_error()),
        };

        if url.scheme() != "mysql" {
            return Err(connection_url_error());
        }

        if url.path_segments().map(|x| x.count()).unwrap_or(0) > 1 {
            return Err(connection_url_error());
        }

        let host = match url.host() {
            Some(Host::Ipv6(host)) => Some(try!(CString::new(host.to_string()))),
            Some(host) => Some(try!(CString::new(host.to_string()))),
            None => None,
        };
        let user = try!(decode_into_cstring(url.username()));
        let password = match url.password() {
            Some(password) => Some(try!(decode_into_cstring(password))),
            None => None,
        };
        let database = match url.path_segments().and_then(|mut iter| iter.nth(0)) {
            Some("") | None => None,
            Some(segment) => Some(try!(CString::new(segment.as_bytes()))),
        };

        let mut ssl_opts: Option<SslOptions> = None;
        for (k, v) in url.query_pairs() {
            if let Some(field) = match &*k {
                "sslkey" => Some(&mut ssl_opts.get_or_insert_with(Default::default).key),
                "sslcert" => Some(&mut ssl_opts.get_or_insert_with(Default::default).cert),
                "sslca" => Some(&mut ssl_opts.get_or_insert_with(Default::default).ca),
                "sslcapath" => Some(&mut ssl_opts.get_or_insert_with(Default::default).capath),
                "sslcipher" => Some(&mut ssl_opts.get_or_insert_with(Default::default).cipher),
                _ => None,
            } {
                *field = Some(CString::new(v.into_owned())?);
            }
        }

        Ok(ConnectionOptions {
            host: host,
            user: user,
            password: password,
            database: database,
            port: url.port(),
            ssl_opts: ssl_opts,
        })
    }

    pub fn host(&self) -> Option<&CStr> {
        self.host.as_ref().map(|x| &**x)
    }

    pub fn user(&self) -> &CStr {
        &self.user
    }

    pub fn password(&self) -> Option<&CStr> {
        self.password.as_ref().map(|x| &**x)
    }

    pub fn database(&self) -> Option<&CStr> {
        self.database.as_ref().map(|x| &**x)
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn ssl_opts(&self) -> Option<&SslOptions> {
        self.ssl_opts.as_ref()
    }
}

#[derive(Debug, Default)]
pub struct SslOptions {
    key: Option<CString>,
    cert: Option<CString>,
    ca: Option<CString>,
    capath: Option<CString>,
    cipher: Option<CString>,
}

impl SslOptions {
    pub fn key(&self) -> Option<&CStr> {
        self.key.as_ref().map(|x| &**x)
    }

    pub fn cert(&self) -> Option<&CStr> {
        self.cert.as_ref().map(|x| &**x)
    }

    pub fn ca(&self) -> Option<&CStr> {
        self.ca.as_ref().map(|x| &**x)
    }

    pub fn capath(&self) -> Option<&CStr> {
        self.capath.as_ref().map(|x| &**x)
    }

    pub fn cipher(&self) -> Option<&CStr> {
        self.cipher.as_ref().map(|x| &**x)
    }
}

fn decode_into_cstring(s: &str) -> ConnectionResult<CString> {
    let decoded = try!(
        percent_decode(s.as_bytes())
            .decode_utf8()
            .map_err(|_| connection_url_error())
    );
    CString::new(decoded.as_bytes()).map_err(Into::into)
}

fn connection_url_error() -> ConnectionError {
    let msg = "MySQL connection URLs must be in the form \
               `mysql://[[user]:[password]@]host[:port][/database]`";
    ConnectionError::InvalidConnectionUrl(msg.into())
}

#[test]
fn urls_with_schemes_other_than_mysql_are_errors() {
    assert!(ConnectionOptions::parse("postgres://localhost").is_err());
    assert!(ConnectionOptions::parse("http://localhost").is_err());
    assert!(ConnectionOptions::parse("file:///tmp/mysql.sock").is_err());
    assert!(ConnectionOptions::parse("socket:///tmp/mysql.sock").is_err());
    assert!(ConnectionOptions::parse("mysql://localhost").is_ok());
}

#[test]
fn urls_must_have_zero_or_one_path_segments() {
    assert!(ConnectionOptions::parse("mysql://localhost/foo/bar").is_err());
    assert!(ConnectionOptions::parse("mysql://localhost/foo").is_ok());
}

#[test]
fn first_path_segment_is_treated_as_database() {
    let foo_cstr = CString::new("foo").unwrap();
    let bar_cstr = CString::new("bar").unwrap();
    assert_eq!(
        Some(&*foo_cstr),
        ConnectionOptions::parse("mysql://localhost/foo")
            .unwrap()
            .database()
    );
    assert_eq!(
        Some(&*bar_cstr),
        ConnectionOptions::parse("mysql://localhost/bar")
            .unwrap()
            .database()
    );
    assert_eq!(
        None,
        ConnectionOptions::parse("mysql://localhost")
            .unwrap()
            .database()
    );
}

#[test]
fn userinfo_should_be_percent_decode() {
    use self::url::percent_encoding::{utf8_percent_encode, USERINFO_ENCODE_SET};

    let username = "x#gfuL?4Zuj{n73m}eeJt0";
    let encoded_username = utf8_percent_encode(username, USERINFO_ENCODE_SET);

    let password = "x/gfuL?4Zuj{n73m}eeJt1";
    let encoded_password = utf8_percent_encode(password, USERINFO_ENCODE_SET);

    let db_url = format!(
        "mysql://{}:{}@localhost/bar",
        encoded_username, encoded_password
    );
    let db_url = Url::parse(&db_url).unwrap();

    let conn_opts = ConnectionOptions::parse(db_url.as_str()).unwrap();
    let username = CString::new(username.as_bytes()).unwrap();
    let password = CString::new(password.as_bytes()).unwrap();
    assert_eq!(username, conn_opts.user);
    assert_eq!(password, conn_opts.password.unwrap());
}

#[test]
fn ipv6_host_not_wrapped_in_brackets() {
    let host1 = CString::new("::1").unwrap();
    let host2 = CString::new("2001:db8:85a3::8a2e:370:7334").unwrap();

    assert_eq!(
        Some(&*host1),
        ConnectionOptions::parse("mysql://[::1]").unwrap().host()
    );
    assert_eq!(
        Some(&*host2),
        ConnectionOptions::parse("mysql://[2001:db8:85a3::8a2e:370:7334]")
            .unwrap()
            .host()
    );
}
