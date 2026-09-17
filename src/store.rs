use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Ios,
    Android,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "ios" => Some(Self::Ios),
            "android" => Some(Self::Android),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenRow {
    pub platform: Platform,
    pub token: String,
    pub voip_token: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AuthRow {
    pub register_key_hash: Option<[u8; 32]>,
    pub wake_secret: Option<[u8; 32]>,
}

pub struct TokenStore {
    conn: Connection,
}

impl TokenStore {
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tokens (
                wake_id TEXT PRIMARY KEY NOT NULL,
                platform TEXT NOT NULL,
                token TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )?;
        let _ = conn.execute_batch("ALTER TABLE tokens ADD COLUMN voip_token TEXT;");
        let _ = conn.execute_batch("ALTER TABLE tokens ADD COLUMN register_key_hash BLOB;");
        let _ = conn.execute_batch("ALTER TABLE tokens ADD COLUMN wake_secret BLOB;");
        Ok(Self { conn })
    }

    pub fn upsert(
        &mut self,
        wake_id: &str,
        platform: Platform,
        token: &str,
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        self.conn.execute(
            "INSERT INTO tokens (wake_id, platform, token, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(wake_id) DO UPDATE SET
                platform = excluded.platform,
                token = excluded.token,
                updated_at = excluded.updated_at",
            params![wake_id, platform.as_str(), token, now],
        )?;
        Ok(())
    }

    pub fn upsert_auth(
        &mut self,
        wake_id: &str,
        platform: Platform,
        token: &str,
        register_key_hash: Option<[u8; 32]>,
        wake_secret: Option<[u8; 32]>,
    ) -> Result<(), rusqlite::Error> {
        let now = now_unix();
        self.conn.execute(
            "INSERT INTO tokens (wake_id, platform, token, updated_at, register_key_hash, wake_secret)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(wake_id) DO UPDATE SET
                platform = excluded.platform,
                token = excluded.token,
                updated_at = excluded.updated_at,
                register_key_hash = COALESCE(excluded.register_key_hash, tokens.register_key_hash),
                wake_secret = COALESCE(excluded.wake_secret, tokens.wake_secret)",
            params![
                wake_id,
                platform.as_str(),
                token,
                now,
                register_key_hash,
                wake_secret
            ],
        )?;
        Ok(())
    }

    pub fn upsert_voip(&mut self, wake_id: &str, voip_token: &str) -> Result<bool, rusqlite::Error> {
        let now = now_unix();
        let n = self.conn.execute(
            "UPDATE tokens SET voip_token = ?1, updated_at = ?2 WHERE wake_id = ?3",
            params![voip_token, now, wake_id],
        )?;
        Ok(n > 0)
    }

    pub fn get(&self, wake_id: &str) -> Result<Option<TokenRow>, rusqlite::Error> {
        self.conn
            .query_row(
                "SELECT platform, token, voip_token FROM tokens WHERE wake_id = ?1",
                params![wake_id],
                |row| {
                    let plat: String = row.get(0)?;
                    let token: String = row.get(1)?;
                    let voip_token: Option<String> = row.get(2)?;
                    Ok((plat, token, voip_token))
                },
            )
            .optional()?
            .map(|(plat, token, voip_token)| {
                Platform::parse(&plat)
                    .map(|platform| TokenRow {
                        platform,
                        token,
                        voip_token,
                    })
                    .ok_or(rusqlite::Error::InvalidQuery)
            })
            .transpose()
    }

    pub fn get_auth(&self, wake_id: &str) -> Result<Option<AuthRow>, rusqlite::Error> {
        self.conn
            .query_row(
                "SELECT register_key_hash, wake_secret FROM tokens WHERE wake_id = ?1",
                params![wake_id],
                |row| {
                    let reg: Option<Vec<u8>> = row.get(0)?;
                    let wake: Option<Vec<u8>> = row.get(1)?;
                    Ok((reg, wake))
                },
            )
            .optional()?
            .map(|(reg, wake)| {
                Ok(AuthRow {
                    register_key_hash: blob32(reg),
                    wake_secret: blob32(wake),
                })
            })
            .transpose()
    }

    pub fn delete_if_token(
        &mut self,
        wake_id: &str,
        token: &str,
    ) -> Result<bool, rusqlite::Error> {
        let n = self.conn.execute(
            "DELETE FROM tokens WHERE wake_id = ?1 AND token = ?2",
            params![wake_id, token],
        )?;
        Ok(n > 0)
    }
}

fn blob32(v: Option<Vec<u8>>) -> Option<[u8; 32]> {
    let b = v?;
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Some(out)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_get_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sqlite");
        let mut s = TokenStore::open(path.to_str().unwrap()).unwrap();
        s.upsert(
            "id1id1id1id1id1id1id1id1id1id1id1id",
            Platform::Ios,
            "tokentokentokentoken",
        )
        .unwrap();
        let row = s
            .get("id1id1id1id1id1id1id1id1id1id1id1id")
            .unwrap()
            .unwrap();
        assert_eq!(row.platform, Platform::Ios);
        assert!(s
            .delete_if_token("id1id1id1id1id1id1id1id1id1id1id1id", "tokentokentokentoken")
            .unwrap());
    }
}
