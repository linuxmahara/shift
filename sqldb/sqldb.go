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

package ethdb

import (
  "database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shiftcurrency/shift/logger"
	"github.com/shiftcurrency/shift/logger/glog"
	"github.com/shiftcurrency/shift/metrics"
  "github.com/mattn/go-sqlite3"

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
	db *DB // sqlite3 instance

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
func NewSQLiteDatabase(file string, cache int) (*LDBDatabase, error) {
	// Calculate the cache allowance for this particular database
	cache = int(float64(cache) * cacheRatio[filepath.Base(file)])
	if cache < 16 {
		cache = 16
	}
	glog.V(logger.Info).Infof("Alloted %dMB cache to %s", cache, file)

	// Open the db
	db, err := db.Open("sqlite3", file)
	// (Re)check for errors and abort if opening of the db failed
	if err != nil {
    glog.V(logger.Error).Infoln("Error opening sqlite3 file %q: %s", err, file)
		return nil, err
	}

  // create the tables if they doesn't exist
  sqlStmt := `
  create table blocks (id integer not null primary key, hash text);
  create table transactions (id integer not null primary key, account text, transaction text);
  `
  _, err = db.Exec(sqlStmt)
  if err != nil {
    glog.V(logger.Error).Infoln("Error creating SQL tables %q: %s", err, sqlStmt)
    return nil, err
  }

	return &SQLDatabase{
		fn: file,
		db: db,
	}, nil
}

// Commits
func (self *SQLDB) Commit() error {
  db.Commit()
	return nil
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
	if err := self.Commit(); err != nil {
		glog.V(logger.Error).Infof("commit '%s' failed: %v\n", self.fn, err)
	}
	self.db.Close()
	glog.V(logger.Error).Infoln("commited and closed db:", self.fn)
}

func (self *SQLDB) DB() *DB {
	return self.db
}

// Meter configures the database metrics collectors and
func (self *SQLDB) Meter(prefix string) {
	// Initialize all the metrics collector at the requested prefix
	self.getTimer = metrics.NewTimer(prefix + "user/gets")
	self.putTimer = metrics.NewTimer(prefix + "user/puts")
	self.delTimer = metrics.NewTimer(prefix + "user/dels")
	self.missMeter = metrics.NewMeter(prefix + "user/misses")
	self.readMeter = metrics.NewMeter(prefix + "user/reads")
	self.writeMeter = metrics.NewMeter(prefix + "user/writes")
	self.compTimeMeter = metrics.NewMeter(prefix + "compact/time")
	self.compReadMeter = metrics.NewMeter(prefix + "compact/input")
	self.compWriteMeter = metrics.NewMeter(prefix + "compact/output")

	// Create a quit channel for the periodic collector and run it
	self.quitLock.Lock()
	self.quitChan = make(chan chan error)
	self.quitLock.Unlock()

	go self.meter(3 * time.Second)
}

// meter periodically retrieves internal leveldb counters and reports them to
// the metrics subsystem.
//
// This is how a stats table look like (currently):
//   Compactions
//    Level |   Tables   |    Size(MB)   |    Time(sec)  |    Read(MB)   |   Write(MB)
//   -------+------------+---------------+---------------+---------------+---------------
//      0   |          0 |       0.00000 |       1.27969 |       0.00000 |      12.31098
//      1   |         85 |     109.27913 |      28.09293 |     213.92493 |     214.26294
//      2   |        523 |    1000.37159 |       7.26059 |      66.86342 |      66.77884
//      3   |        570 |    1113.18458 |       0.00000 |       0.00000 |       0.00000
func (self *SQLDB) meter(refresh time.Duration) {
	// Create the counters to store current and previous values
	counters := make([][]float64, 2)
	for i := 0; i < 2; i++ {
		counters[i] = make([]float64, 3)
	}
	// Iterate ad infinitum and collect the stats
	for i := 1; ; i++ {
		// Retrieve the database stats
		stats, err := self.db.GetProperty("leveldb.stats")
		if err != nil {
			glog.V(logger.Error).Infof("failed to read database stats: %v", err)
			return
		}
		// Find the compaction table, skip the header
		lines := strings.Split(stats, "\n")
		for len(lines) > 0 && strings.TrimSpace(lines[0]) != "Compactions" {
			lines = lines[1:]
		}
		if len(lines) <= 3 {
			glog.V(logger.Error).Infof("compaction table not found")
			return
		}
		lines = lines[3:]

		// Iterate over all the table rows, and accumulate the entries
		for j := 0; j < len(counters[i%2]); j++ {
			counters[i%2][j] = 0
		}
		for _, line := range lines {
			parts := strings.Split(line, "|")
			if len(parts) != 6 {
				break
			}
			for idx, counter := range parts[3:] {
				if value, err := strconv.ParseFloat(strings.TrimSpace(counter), 64); err != nil {
					glog.V(logger.Error).Infof("compaction entry parsing failed: %v", err)
					return
				} else {
					counters[i%2][idx] += value
				}
			}
		}
		// Update all the requested meters
		if self.compTimeMeter != nil {
			self.compTimeMeter.Mark(int64((counters[i%2][0] - counters[(i-1)%2][0]) * 1000 * 1000 * 1000))
		}
		if self.compReadMeter != nil {
			self.compReadMeter.Mark(int64((counters[i%2][1] - counters[(i-1)%2][1]) * 1024 * 1024))
		}
		if self.compWriteMeter != nil {
			self.compWriteMeter.Mark(int64((counters[i%2][2] - counters[(i-1)%2][2]) * 1024 * 1024))
		}
		// Sleep a bit, then repeat the stats collection
		select {
		case errc := <-self.quitChan:
			// Quit requesting, stop hammering the database
			errc <- nil
			return

		case <-time.After(refresh):
			// Timeout, gather a new set of stats
		}
	}
}
