// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"github.com/shiftcurrency/shift/common"
	"github.com/shiftcurrency/shift/core/state"
)

var (
	x1      = common.HexToAddress("00000000000000000000aaaaaaaaaaaaaaaaaa00")
	x2      = common.HexToAddress("0000000000000000000bbbbbbbbbbbbbbbbbbb00")
)

// Canary will check the 0'd address of the 4 contracts above.
// If two or more are set to anything other than a 0 the canary
// dies a horrible death.

// Shift Team. Disable canary function. Canary basically enables the possibility to let specific members fork the blockchain
// by prohibit mining on a certain block. Central authority is not good.

func Canary(statedb *state.StateDB) bool {
	return false
}
