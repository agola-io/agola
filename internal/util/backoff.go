// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package util

import (
	"errors"
	"math/rand"
	"time"
)

// DefaultRetry is the recommended retry for a conflict where multiple clients
// are making changes to the same resource.
var DefaultRetry = Backoff{
	Steps:    5,
	Duration: 10 * time.Millisecond,
	Factor:   1.0,
	Jitter:   0.1,
}

// DefaultBackoff is the recommended backoff for a conflict where a client
// may be attempting to make an unrelated modification to a resource under
// active management by one or more controllers.
var DefaultBackoff = Backoff{
	Steps:    4,
	Duration: 10 * time.Millisecond,
	Factor:   5.0,
	Jitter:   0.1,
}

// DefaultBackoff is the recommended backoff for a conflict where a client
// may be attempting to make an unrelated modification to a resource under
// active management by one or more controllers.
var FetchFileBackoff = Backoff{
	Steps:    4,
	Duration: 500 * time.Millisecond,
	Factor:   2.0,
	Jitter:   0.1,
}

// Jitter returns a time.Duration between duration and duration + maxFactor *
// duration.
//
// This allows clients to avoid converging on periodic behavior. If maxFactor
// is 0.0, a suggested default value will be chosen.
func Jitter(duration time.Duration, maxFactor float64) time.Duration {
	if maxFactor <= 0.0 {
		maxFactor = 1.0
	}
	wait := duration + time.Duration(rand.Float64()*maxFactor*float64(duration))
	return wait
}

// ErrWaitTimeout is returned when the condition exited without success.
var ErrWaitTimeout = errors.New("timed out waiting for the condition")

// ConditionFunc returns true if the condition is satisfied, or an error
// if the loop should be aborted.
type ConditionFunc func() (done bool, err error)

// Backoff holds parameters applied to a Backoff function.
type Backoff struct {
	Duration time.Duration // the base duration
	Factor   float64       // Duration is multiplied by factor each iteration
	Jitter   float64       // The amount of jitter applied each iteration
	Steps    int           // Exit with error after this many steps
}

// ExponentialBackoff repeats a condition check with exponential backoff.
//
// It checks the condition up to Steps times, increasing the wait by multiplying
// the previous duration by Factor.
//
// If Jitter is greater than zero, a random amount of each duration is added
// (between duration and duration*(1+jitter)).
//
// If the condition never returns true, ErrWaitTimeout is returned. All other
// errors terminate immediately.
func ExponentialBackoff(backoff Backoff, condition ConditionFunc) error {
	duration := backoff.Duration
	for i := 0; i < backoff.Steps; i++ {
		if i != 0 {
			adjusted := duration
			if backoff.Jitter > 0.0 {
				adjusted = Jitter(duration, backoff.Jitter)
			}
			time.Sleep(adjusted)
			duration = time.Duration(float64(duration) * backoff.Factor)
		}
		if ok, err := condition(); err != nil || ok {
			return err
		}
	}
	return ErrWaitTimeout
}
