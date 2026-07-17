import json
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path


class Storage:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.migrate()

    def migrate(self):
        with self.lock, self.db:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS messages (
              id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL,
              modem_index INTEGER, device TEXT NOT NULL DEFAULT 'IG830',
              sender TEXT NOT NULL, body TEXT NOT NULL, received_at TEXT,
              stored_at TEXT NOT NULL, filtered INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS deliveries (
              id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
              channel TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
              next_attempt TEXT, last_error TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
              UNIQUE(message_id, channel)
            );
            CREATE TABLE IF NOT EXISTS signal_history (
              id INTEGER PRIMARY KEY, recorded_at TEXT NOT NULL, dbm INTEGER,
              level INTEGER, operator TEXT, registration TEXT, registered INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS audit (
              id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, action TEXT NOT NULL,
              detail TEXT NOT NULL DEFAULT '', remote TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS telegram_message_links (
              chat_id TEXT NOT NULL, telegram_message_id INTEGER NOT NULL,
              message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
              created_at TEXT NOT NULL,
              PRIMARY KEY(chat_id,telegram_message_id)
            );
            CREATE TABLE IF NOT EXISTS telegram_replies (
              update_id INTEGER PRIMARY KEY, chat_id TEXT NOT NULL,
              telegram_message_id INTEGER NOT NULL,
              message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
              recipient_masked TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
              last_error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_stored ON messages(stored_at DESC);
            CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(status,next_attempt);
            CREATE INDEX IF NOT EXISTS idx_signal_time ON signal_history(recorded_at DESC);
            CREATE INDEX IF NOT EXISTS idx_telegram_links_message ON telegram_message_links(message_id);
            """)

    @staticmethod
    def now():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def store_message(self, fingerprint, sms, filtered=False):
        with self.lock, self.db:
            self.db.execute("INSERT OR IGNORE INTO messages(fingerprint,modem_index,sender,body,received_at,stored_at,filtered) VALUES(?,?,?,?,?,?,?)",
                            (fingerprint, sms.get("index"), sms.get("sender", ""), sms.get("message", ""), sms.get("received_at", ""), self.now(), int(filtered)))
            row = self.db.execute("SELECT id FROM messages WHERE fingerprint=?", (fingerprint,)).fetchone()
            return row["id"]

    def transform_message_bodies(self, transform):
        with self.lock, self.db:
            rows = self.db.execute("SELECT id,body FROM messages").fetchall()
            updates = []
            for row in rows:
                transformed = transform(row["body"])
                if transformed != row["body"]:
                    updates.append((transformed, row["id"]))
            self.db.executemany("UPDATE messages SET body=? WHERE id=?", updates)
            return len(updates)

    def deduplicate_messages(self):
        """Merge duplicate rows for the same physical modem message."""
        removed = 0
        with self.lock, self.db:
            groups = self.db.execute("""SELECT device,modem_index,sender,received_at
              FROM messages GROUP BY device,modem_index,sender,received_at HAVING COUNT(*)>1""").fetchall()
            for group in groups:
                rows = self.db.execute("""SELECT id,body FROM messages
                  WHERE device=? AND modem_index IS ? AND sender=? AND received_at IS ?
                  ORDER BY length(body) DESC,id""",
                  (group["device"], group["modem_index"], group["sender"], group["received_at"])).fetchall()
                keep_id = rows[0]["id"]
                ids = [row["id"] for row in rows]
                for duplicate_id in ids[1:]:
                    self._move_deliveries(duplicate_id, keep_id)
                    self.db.execute("DELETE FROM messages WHERE id=?", (duplicate_id,))
                    removed += 1
        return removed

    def _move_deliveries(self, source_id, target_id):
        self.db.execute("UPDATE telegram_message_links SET message_id=? WHERE message_id=?", (target_id, source_id))
        self.db.execute("UPDATE telegram_replies SET message_id=? WHERE message_id=?", (target_id, source_id))
        deliveries = self.db.execute("SELECT * FROM deliveries WHERE message_id=?", (source_id,)).fetchall()
        for delivery in deliveries:
            existing = self.db.execute("SELECT * FROM deliveries WHERE message_id=? AND channel=?", (target_id, delivery["channel"])).fetchone()
            if existing is None:
                self.db.execute("UPDATE deliveries SET message_id=? WHERE id=?", (target_id, delivery["id"]))
            elif delivery["status"] == "success" and existing["status"] != "success":
                self.db.execute("""UPDATE deliveries SET status='success',attempts=?,next_attempt=NULL,
                  last_error='',updated_at=? WHERE id=?""", (max(existing["attempts"], delivery["attempts"]), max(existing["updated_at"], delivery["updated_at"]), existing["id"]))

    def merge_contained_message_parts(self):
        """Remove legacy text-mode fragments when a complete PDU message exists."""
        removed = 0
        with self.lock, self.db:
            groups = self.db.execute("""SELECT device,sender,received_at
              FROM messages GROUP BY device,sender,received_at HAVING COUNT(*)>1""").fetchall()
            for group in groups:
                rows = self.db.execute("""SELECT id,modem_index,body FROM messages
                  WHERE device=? AND sender=? AND received_at=? ORDER BY length(body) DESC,id""",
                  (group["device"], group["sender"], group["received_at"])).fetchall()
                keep = rows[0]
                keep_body = keep["body"] or ""
                for row in rows[1:]:
                    body = row["body"] or ""
                    index_distance = abs((row["modem_index"] or 0) - (keep["modem_index"] or 0))
                    if not body or body not in keep_body or index_distance > 10:
                        continue
                    self._move_deliveries(row["id"], keep["id"])
                    self.db.execute("DELETE FROM messages WHERE id=?", (row["id"],))
                    removed += 1
        return removed

    def enqueue(self, message_id, channels):
        now = self.now()
        with self.lock, self.db:
            for channel in channels:
                self.db.execute("INSERT OR IGNORE INTO deliveries(message_id,channel,next_attempt,updated_at) VALUES(?,?,?,?)", (message_id, channel, now, now))

    def due_deliveries(self, limit=30):
        with self.lock:
            rows = self.db.execute("""SELECT d.*,m.sender,m.body,m.received_at,m.modem_index
              FROM deliveries d JOIN messages m ON m.id=d.message_id
              WHERE d.status IN ('pending','failed') AND (d.next_attempt IS NULL OR d.next_attempt<=?)
              ORDER BY d.updated_at LIMIT ?""", (self.now(), limit)).fetchall()
            return [dict(x) for x in rows]

    def delivery_result(self, delivery_id, ok, error=""):
        with self.lock, self.db:
            row = self.db.execute("SELECT attempts FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            attempts = (row["attempts"] if row else 0) + 1
            delay = min(3600, 5 * (2 ** min(attempts - 1, 9)))
            next_attempt = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat(timespec="seconds")
            self.db.execute("UPDATE deliveries SET status=?,attempts=?,next_attempt=?,last_error=?,updated_at=? WHERE id=?",
                            ("success" if ok else "failed", attempts, None if ok else next_attempt, error[:1000], self.now(), delivery_id))

    def retry_delivery(self, delivery_id):
        with self.lock, self.db:
            self.db.execute("UPDATE deliveries SET status='pending',next_attempt=?,last_error='',updated_at=? WHERE id=?", (self.now(), self.now(), delivery_id))

    def link_telegram_message(self, chat_id, telegram_message_id, message_id):
        with self.lock, self.db:
            self.db.execute("""INSERT OR REPLACE INTO telegram_message_links
              (chat_id,telegram_message_id,message_id,created_at) VALUES(?,?,?,?)""",
              (str(chat_id), int(telegram_message_id), int(message_id), self.now()))

    def telegram_reply_target(self, chat_id, telegram_message_id):
        with self.lock:
            row = self.db.execute("""SELECT m.id message_id,m.sender,m.received_at,l.created_at linked_at
              FROM telegram_message_links l JOIN messages m ON m.id=l.message_id
              WHERE l.chat_id=? AND l.telegram_message_id=?""",
              (str(chat_id), int(telegram_message_id))).fetchone()
            return dict(row) if row else None

    def claim_telegram_reply(self, update_id, chat_id, telegram_message_id, message_id, recipient_masked):
        now = self.now()
        with self.lock, self.db:
            cursor = self.db.execute("""INSERT OR IGNORE INTO telegram_replies
              (update_id,chat_id,telegram_message_id,message_id,recipient_masked,status,created_at,updated_at)
              VALUES(?,?,?,?,?,'processing',?,?)""",
              (int(update_id), str(chat_id), int(telegram_message_id), int(message_id), recipient_masked, now, now))
            return cursor.rowcount == 1

    def finish_telegram_reply(self, update_id, status, error=""):
        with self.lock, self.db:
            self.db.execute("""UPDATE telegram_replies SET status=?,last_error=?,updated_at=?
              WHERE update_id=?""", (status, str(error)[:1000], self.now(), int(update_id)))

    @staticmethod
    def _message_timestamp(value):
        raw = str(value or "").strip()
        modem_time = re.fullmatch(r"(\d{2})/(\d{2})/(\d{2}),(\d{2}):(\d{2}):(\d{2})([+-])(\d{2})", raw)
        if modem_time:
            parts = [int(modem_time.group(index)) for index in range(1, 7)]
            offset_minutes = int(modem_time.group(8)) * 15 * (1 if modem_time.group(7) == "+" else -1)
            zone = timezone(timedelta(minutes=offset_minutes))
            return datetime(2000 + parts[0], *parts[1:], tzinfo=zone).timestamp()
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            return None

    def list_messages(self, query="", page=1, page_size=30, order="desc"):
        where, args = "", []
        if query:
            where = "WHERE m.sender LIKE ? OR m.body LIKE ?"
            args = [f"%{query}%", f"%{query}%"]
        with self.lock:
            total = self.db.execute(f"SELECT COUNT(*) n FROM messages m {where}", args).fetchone()["n"]
            rows = self.db.execute(f"""SELECT m.*,
              COALESCE(json_group_array(json_object('id',d.id,'channel',d.channel,'status',d.status,'attempts',d.attempts,'error',d.last_error)),'[]') deliveries
              FROM messages m LEFT JOIN deliveries d ON d.message_id=m.id {where}
              GROUP BY m.id""", args).fetchall()
            out=[]
            for row in rows:
                item=dict(row); item["deliveries"]=json.loads(item["deliveries"]); out.append(item)
            def sort_key(item):
                timestamp = self._message_timestamp(item.get("received_at"))
                if timestamp is None:
                    timestamp = self._message_timestamp(item.get("stored_at"))
                return (timestamp if timestamp is not None else float("-inf"), item["id"])
            descending = str(order).lower() != "asc"
            out.sort(key=sort_key, reverse=descending)
            start = (page - 1) * page_size
            return {"items":out[start:start + page_size],"total":total,"page":page,"page_size":page_size,"sort":"desc" if descending else "asc"}

    def stats(self):
        with self.lock:
            messages = self.db.execute("SELECT COUNT(*) n FROM messages").fetchone()["n"]
            today = self.db.execute("SELECT COUNT(*) n FROM messages WHERE stored_at>=date('now')").fetchone()["n"]
            delivery = {r["status"]: r["n"] for r in self.db.execute("SELECT status,COUNT(*) n FROM deliveries GROUP BY status")}
            senders = [dict(r) for r in self.db.execute("SELECT sender,COUNT(*) count FROM messages GROUP BY sender ORDER BY count DESC LIMIT 8")]
            return {"messages":messages,"today":today,"deliveries":delivery,"top_senders":senders}

    def add_signal(self, runtime):
        with self.lock, self.db:
            self.db.execute("INSERT INTO signal_history(recorded_at,dbm,level,operator,registration,registered) VALUES(?,?,?,?,?,?)",
                            (self.now(), runtime.get("signal_dbm"), runtime.get("signal_level"), runtime.get("operator", ""), runtime.get("registration", ""), int(runtime.get("registered", False))))

    def signal_history(self, hours=24):
        since = (datetime.now(timezone.utc)-timedelta(hours=hours)).isoformat(timespec="seconds")
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT recorded_at,dbm,level,operator,registration,registered FROM signal_history WHERE recorded_at>=? ORDER BY id", (since,))]

    def audit(self, action, detail="", remote=""):
        with self.lock, self.db:
            self.db.execute("INSERT INTO audit(created_at,action,detail,remote) VALUES(?,?,?,?)", (self.now(), action, detail[:2000], remote))

    def list_audit(self, limit=100):
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    def retention(self, days):
        before = (datetime.now(timezone.utc)-timedelta(days=days)).isoformat(timespec="seconds")
        with self.lock, self.db:
            self.db.execute("DELETE FROM messages WHERE stored_at<?", (before,))
            self.db.execute("DELETE FROM signal_history WHERE recorded_at<?", (before,))
            self.db.execute("DELETE FROM audit WHERE created_at<?", (before,))
            self.db.execute("DELETE FROM telegram_replies WHERE created_at<?", (before,))
