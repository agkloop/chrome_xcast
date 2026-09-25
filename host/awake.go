package main

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"
)

// A relayed cast, and a file played from the command line, stop when this
// computer goes to idle sleep: the TV reads from it. So while such a cast
// plays, and for pauseAwake into a pause, the helper holds macOS's "prevent
// idle system sleep" assertion. The display may still sleep, and closing a
// laptop's lid still puts it to sleep. A direct cast needs nothing: the TV
// plays on its own.
//
// The assertion is held by /usr/bin/caffeinate (the helper has no cgo). It
// runs inside the helper's sandbox, which allows that one program and the
// power-management service it talks to, and it exits by itself if the helper
// dies (-w).
const pauseAwake = 30 * time.Minute

type waker struct {
	mu    sync.Mutex
	start func() func() // begins holding; returns the release, or nil if it could not
	stop  func()        // non-nil while held
	timer *time.Timer   // a release scheduled during a pause
}

// awakeStart is how a waker begins holding (a stub in tests).
var awakeStart = caffeinate

func newWaker() *waker { return &waker{start: awakeStart} }

// hold keeps the computer awake until release.
func (w *waker) hold() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cancelTimer()
	if w.stop == nil && w.start != nil {
		w.stop = w.start()
	}
}

// releaseIn lets the computer sleep after d, unless hold comes first.
func (w *waker) releaseIn(d time.Duration) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stop == nil || w.timer != nil {
		return
	}
	var t *time.Timer
	t = time.AfterFunc(d, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.timer == t { // not overtaken by hold or release
			w.releaseLocked()
		}
	})
	w.timer = t
}

func (w *waker) release() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.releaseLocked()
}

func (w *waker) releaseLocked() {
	w.cancelTimer()
	if w.stop != nil {
		w.stop()
		w.stop = nil
	}
}

func (w *waker) held() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stop != nil
}

func (w *waker) cancelTimer() {
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
}

func caffeinate() func() {
	if runtime.GOOS != "darwin" {
		return nil
	}
	cmd := exec.Command("/usr/bin/caffeinate", "-i", "-w", strconv.Itoa(os.Getpid()))
	if err := cmd.Start(); err != nil {
		// An older sandbox profile (install.sh not run again): casting works,
		// only the computer may sleep.
		debugf("keep awake: %v", err)
		return nil
	}
	return func() {
		_ = cmd.Process.Kill()
		go cmd.Wait() // never blocks the caller, whatever became of it
	}
}
