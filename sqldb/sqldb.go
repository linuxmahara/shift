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
  "database/sql"
	"path/filepath"
	"sync"

	"github.com/shiftcurrency/shift/logger"
	"github.com/shiftcurrency/shift/logger/glog"
  _ "github.com/mattn/go-sqlite3"

	gometrics "github.com/rcrowley/go-metrics"
)

var OpenFileLimit = 64

// cacheRatio specifies how the total alloted cache is distributed between the
// various system databases.
var cacheRatio = map[string]float64{
	"dapp":      2.0 / 13.0,
	"chaindata": 11.0 / 13.0,
}

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

// NewSQLiteDatabase returns a sqlite3 wrapped object. sqlite3 does not persist data by
// it self but requires a background poller which syncs every X. `Flush` should be called
// when data needs to be stored and written to disk.
func NewSQLiteDatabase(file string, cache int) (*SQLDB, error) {
	// Calculate the cache allowance for this particular database
	cache = int(float64(cache) * cacheRatio[filepath.Base(file)])
	if cache < 16 {
		cache = 16
	}
	glog.V(logger.Info).Infof("Alloted %dMB cache to %s", cache, file)

	// Open the db
	db, err := sql.Open("sqlite3", file)
	// (Re)check for errors and abort if opening of the db failed
	if err != nil {
    glog.V(logger.Error).Infoln("Error opening sqlite3 file %q: %s", err, file)
		return nil, err
	}

  // create the tables if they doesn't exist
  sqlStmt := `
  create table blocks (id integer not null primary key, hash text);
  create table "transactions" (id integer not null primary key, account text, "transaction" text);
  `
  _, err = db.Exec(sqlStmt)
  if err != nil {
    glog.V(logger.Error).Infoln("Error creating SQL tables %q: %s", err, sqlStmt)
    return nil, err
  }

	return &SQLDB{
		fn: file,
		db: db,
	}, nil
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
	glog.V(logger.Error).Infoln("commited and closed db:", self.fn)
}

func (self *SQLDB) DB() *sql.DB {
	return self.db
}
