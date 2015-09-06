// Copyright 2015 The Shift Developers
// This file is part of the shift library.
//
// The shift library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The shift library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package sqldb

import (
  "os"
  "database/sql"
	"sync"

	"github.com/shiftcurrency/shift/logger"
	"github.com/shiftcurrency/shift/logger/glog"
  _ "github.com/mattn/go-sqlite3"

	gometrics "github.com/rcrowley/go-metrics"
)

var db_version uint64 = 1

type SQLDB struct {
	fn string      // filename for reporting
	db *sql.DB // sqlite3 instance

	getTimer       gometrics.Timer // Timer for measuring the database get request counts and latencies
	putTimer       gometrics.Timer // Timer for measuring the database put request counts and latencies
	delTimer       gometrics.Timer // Timer for measuring the database delete request counts and latencies
	missMeter      gometrics.Meter // Meter for measuring the missed database get requests
	readMeter      gometrics.Meter // Meter for measuring the database get request data usage
	writeMeter     gometrics.Meter // Meter for measuring the database put request data usage
	compTimeMeter  gometrics.Meter // Meter for measuring the total time spent in database compaction
	compReadMeter  gometrics.Meter // Meter for measuring the data read during compaction
	compWriteMeter gometrics.Meter // Meter for measuring the data written during compaction

	quitLock sync.Mutex      // Mutex protecting the quit channel access
	quitChan chan chan error // Quit channel to stop the metrics collection before closing the database
}

func checkExists(db *sql.DB, query string) (bool, error) {
  rows, err := db.Query(query)
  if err != nil {
    glog.V(logger.Error).Infoln("Error checking existence", err, query)
    return false, err
  }
  defer rows.Close()

  return rows.Next(), nil;
}

func checkTables(db *sql.DB) (bool, error) {
  return checkExists(db, `SELECT name FROM sqlite_master WHERE type='table' AND name='status'`)
}

func checkVersion(db *sql.DB) (bool, error) {
  query := `SELECT version FROM status ORDER BY created DESC LIMIT 1`;
  rows, err := db.Query(query)
  if err != nil {
    glog.V(logger.Error).Infoln("Error checking version", err, query)
    return false, err
  }
  defer rows.Close()

  if rows.Next() {
    var v uint64
    rows.Scan(&v)
    return (v == db_version), nil
  }

  return false, nil
}

// NewSQLiteDatabase returns a sqlite3 wrapped object. sqlite3 does not persist data by
// it self but requires a background poller which syncs every X. `Flush` should be called
// when data needs to be stored and written to disk.
func NewSQLiteDatabase(file string) (*SQLDB, error) {
	// Open the db
	db, err := sql.Open("sqlite3", file)
	// (Re)check for errors and abort if opening of the db failed
	if err != nil {
		return nil, err
	}

  var cv bool = false
  var ct bool = false
  ct, err = checkTables(db)
  if err != nil {
		return nil, err
	}

  if ct {
    cv, err = checkVersion(db)
    if err != nil {
		  return nil, err
	  }
  }

  // tables exist with version mismatch, drop and recreate
  if ct && !cv {
    glog.V(logger.Info).Infoln("Dropping old SQL DB", file)
    db.Close()
    os.Remove(file)

    // Open the db
  	db, err = sql.Open("sqlite3", file)
  	// (Re)check for errors and abort if opening of the db failed
  	if err != nil {
  		return nil, err
  	}
    ct = false
  }

  if !ct {
    glog.V(logger.Info).Infoln("Creating new SQL DB", file)
    // create the tables if they doesn't exist
    sqlStmt := `
      CREATE TABLE status (
        lastblock UNSIGNED BIG INT NOT NULL,
        created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        version INT NOT NULL
      );
      INSERT INTO status(lastblock, version)
      VALUES (0, ?);

      CREATE TABLE blocks (
        number INTEGER NOT NULL PRIMARY KEY,
        hash TEXT
      );

      CREATE TABLE "transactions" (
        id INTEGER NOT NULL PRIMARY KEY,
        account TEXT NOT NULL,
        thash TEXT NOT NULL
      );
    `

    _, err = db.Exec(sqlStmt, db_version)
    if err != nil {
      glog.V(logger.Error).Infoln("Error creating SQL tables %q: %s", err, sqlStmt)
      return nil, err
    }
  } else {
    glog.V(logger.Info).Infoln("Loading existing SQL DB", file)
  }

	return &SQLDB{
		fn: file,
		db: db,
	}, nil
}

func (self *SQLDB) Refresh() {

}

func (self *SQLDB) Close() {
	// Stop the metrics collection to avoid internal database races
	self.quitLock.Lock()
	defer self.quitLock.Unlock()

	if self.quitChan != nil {
		errc := make(chan error)
		self.quitChan <- errc
		if err := <-errc; err != nil {
			glog.V(logger.Error).Infof("metrics failure in '%s': %v\n", self.fn, err)
		}
	}
	// Commit and close the database
	/*if err := self.Commit(); err != nil {
		glog.V(logger.Error).Infof("commit '%s' failed: %v\n", self.fn, err)
	}*/

	self.db.Close()
	glog.V(logger.Error).Infoln("Closed SQL DB:", self.fn)
}

func (self *SQLDB) DB() *sql.DB {
	return self.db
}
