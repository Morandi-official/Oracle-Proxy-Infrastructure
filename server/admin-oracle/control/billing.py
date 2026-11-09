"""Account anchored 30-day ledger; OCI/server calendar billing remains separate."""
import datetime as dt

SECONDS=30*86400

class Ledger:
    def __init__(self,db,now):
        self.db=db;self.now=now
        db.executescript("""
        CREATE TABLE IF NOT EXISTS user_cycles(user_id TEXT PRIMARY KEY,assigned_at INTEGER NOT NULL,basis TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cycle_usage(user_id TEXT,start_at INTEGER,rx INTEGER NOT NULL,tx INTEGER NOT NULL,estimated INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(user_id,start_at));
        CREATE TABLE IF NOT EXISTS cycle_daily(user_id TEXT,start_at INTEGER,day INTEGER,rx INTEGER NOT NULL,tx INTEGER NOT NULL,PRIMARY KEY(user_id,start_at,day));
        """)

    def anchor(self,user_id,assigned_at=None,basis='root_audit'):
        row=self.db.execute('SELECT * FROM user_cycles WHERE user_id=?',(user_id,)).fetchone()
        if row and (assigned_at is None or row['basis'].startswith('account:')):
            if assigned_at is not None and (row['assigned_at']!=assigned_at or row['basis']!='account:'+basis):
                raise ValueError('ACCOUNT_CYCLE_ANCHOR_IMMUTABLE')
            return
        if assigned_at is None:
            first=self.db.execute("SELECT min(at) FROM audit WHERE resource=? AND action='user.updated'",(user_id,)).fetchone()[0]
            assigned_at=first if first is not None else int(self.now())
        else:basis='account:'+basis
        self.db.execute('INSERT OR REPLACE INTO user_cycles VALUES (?,?,?)',(user_id,assigned_at,basis))
        # Seed current cycle once. Do not pretend historical data was collected at finer resolution.
        start=self.window(user_id)['start_at'];now=int(self.now())
        if row:self.db.execute('DELETE FROM cycle_usage WHERE user_id=?',(user_id,));self.db.execute('DELETE FROM cycle_daily WHERE user_id=?',(user_id,))
        first_month=dt.datetime.fromtimestamp(start,dt.timezone.utc).strftime('%Y-%m')
        last_month=dt.datetime.fromtimestamp(now,dt.timezone.utc).strftime('%Y-%m')
        old=self.db.execute("SELECT coalesce(sum(rx),0),coalesce(sum(tx),0) FROM usage WHERE kind='user' AND key=? AND month>=? AND month<=?",(user_id,first_month,last_month)).fetchone()
        # Legacy calendar totals conservatively include boundary days; flag that initial cycle.
        self.db.execute('INSERT OR IGNORE INTO cycle_usage VALUES (?,?,?,?,?)',(user_id,start,old[0],old[1],int(bool(old[0] or old[1]))))

    def window(self,user_id):
        row=self.db.execute('SELECT * FROM user_cycles WHERE user_id=?',(user_id,)).fetchone()
        if not row:self.anchor(user_id);row=self.db.execute('SELECT * FROM user_cycles WHERE user_id=?',(user_id,)).fetchone()
        anchor=row['assigned_at'];start=anchor+max(0,(int(self.now())-anchor)//SECONDS)*SECONDS
        usage=self.db.execute('SELECT estimated FROM cycle_usage WHERE user_id=? AND start_at=?',(user_id,start)).fetchone()
        return {'assigned_at':anchor,'start_at':start,'end_at':start+SECONDS,'duration_days':30,'assignment_basis':row['basis'],'usage_estimated':bool(usage and usage[0])}

    def used(self,user_id):
        start=self.window(user_id)['start_at']
        row=self.db.execute('SELECT rx,tx FROM cycle_usage WHERE user_id=? AND start_at=?',(user_id,start)).fetchone()
        return {'rx':row[0],'tx':row[1]} if row else {'rx':0,'tx':0}

    def add(self,user_id,rx,tx):
        start=self.window(user_id)['start_at'];day=int(self.now())//86400*86400
        self.db.execute('INSERT INTO cycle_usage VALUES (?,?,?,?,0) ON CONFLICT(user_id,start_at) DO UPDATE SET rx=rx+excluded.rx,tx=tx+excluded.tx',(user_id,start,rx,tx))
        self.db.execute('INSERT INTO cycle_daily VALUES (?,?,?,?,?) ON CONFLICT(user_id,start_at,day) DO UPDATE SET rx=rx+excluded.rx,tx=tx+excluded.tx',(user_id,start,day,rx,tx))
