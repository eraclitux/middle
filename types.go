// Copyright (c) 2015 Andrea Masi. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE.txt file.

package middle

import (
	"sync"
)

// FIXME drop sessions every x time or memory leak here.
var sessions map[string]struct{} = make(map[string]struct{})

var sessionsMut sync.RWMutex

// Hasher define a way to generalize
// credentials retrieving from different
// backends.
// MUST be concurrency safe.
type Hasher interface {
	// GetHash retrieves hashed password from
	// backend for user u.
	// It returns error if user is not found.
	GetHash(u string) ([]byte, error)
}
