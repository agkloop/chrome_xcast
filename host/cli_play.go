package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const playUsage = `Cast a video file from this computer to a TV.

  xcast [-d tv] [-at 1:23:45] [-title text] <file>

  -d tv        the TV: part of its name, or its IP address. Without it, XCast
               lists the TVs it finds and asks.
  -at time     where to start: 1:23:45, 23:45 or seconds
  -title text  what the TV shows as the title (default "XCast"). Every Cast
               controller on your network can read it.

The file is served to the TV from this computer, so this command keeps
running while the video plays. Nothing is converted: the TV has to be able to
play the file as it is (.mp4, .m4v, .mov, .webm, .mp3, .m4a, .aac).
`

const playKeys = `  p          pause or play           f [secs]   forward (30)
  s 1:23:45  jump to a position      b [secs]   back (10)
  v 0-100    volume                  q          stop and quit`

// cliPlay is `xcast <file>`: pick a TV, cast the file, then a small remote on
// standard input.
func cliPlay(args []string) {
	fs := flag.NewFlagSet("xcast", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	tv := fs.String("d", "", "")
	at := fs.String("at", "", "")
	title := fs.String("title", "XCast", "")
	// Set by the installed wrapper: the real path of the file, which is the one
	// path its sandbox lets this process read.
	resolved := fs.String("resolved", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, playUsage)
		os.Exit(2)
	}
	file := *resolved
	if file == "" {
		file, _ = filepath.Abs(fs.Arg(0))
	}
	start := 0.0
	if *at != "" {
		var err error
		if start, err = parseClock(*at); err != nil {
			log.Fatalf("-at %s: %v", *at, err)
		}
	}

	events := make(chan map[string]any, 32)
	h := newHost(func(v any) {
		b, _ := json.Marshal(v)
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			select {
			case events <- m:
			default: // a remote that does not read must not block the cast
			}
		}
	})
	// Fail on a file the TV cannot play before anyone is asked anything.
	if _, err := localFileType(file); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Looking for TVs…")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	devs, err := discover(ctx, 2*time.Second, func(Device) {}) // listed below, once, in order
	cancel()
	if err != nil {
		log.Fatalf("TV search failed: %v", err)
	}
	for i := range devs {
		devs[i].Known = h.pins.known(devs[i].ID)
	}
	sort.SliceStable(devs, func(i, j int) bool { return devs[i].Known && !devs[j].Known })
	d, err := chooseDevice(devs, *tv, os.Stdin, os.Stdout)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Connecting to %s…\n", d.Name)
	ctx, cancel = context.WithTimeout(context.Background(), 75*time.Second)
	_, err = h.dispatch(ctx, request{
		Type:   "cast",
		Device: &deviceRef{ID: d.ID, Name: d.Name, Host: d.Host, Port: d.Port},
		Media:  &mediaReq{file: file, Title: *title, CurrentTime: start},
	})
	cancel()
	if err != nil {
		h.shutdown()
		log.Fatal(err)
	}
	fmt.Printf("Playing %s on %s. Keep this running: the TV gets the video from here.\n%s\n", filepath.Base(fs.Arg(0)), d.Name, playKeys)

	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			lines <- sc.Text()
		}
		// Standard input closed (run from a script): keep playing until a signal.
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	stop := func(code int) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = h.control(ctx, "stop", 0)
		cancel()
		h.shutdown()
		os.Exit(code)
	}
	state := ""
	for {
		select {
		case <-sig:
			fmt.Println()
			stop(0)
		case ev := <-events:
			switch ev["type"] {
			case "disconnected":
				fmt.Println("Lost the TV:", ev["reason"])
				h.shutdown()
				os.Exit(1)
			case "media":
				s, _ := ev["state"].(string)
				pos, _ := ev["currentTime"].(float64)
				total, _ := ev["duration"].(float64)
				if reason, _ := ev["idleReason"].(string); s == "IDLE" && reason != "" {
					fmt.Println(map[string]string{"FINISHED": "Finished.", "ERROR": "The TV could not play this file. It may be in a format or codec it does not support."}[reason])
					h.shutdown()
					if reason == "ERROR" {
						os.Exit(1)
					}
					os.Exit(0)
				}
				if s != state && s != "IDLE" {
					state = s
					line := strings.ToUpper(s[:1]) + strings.ToLower(s[1:]) + "  " + clock(pos)
					if total > 0 {
						line += " / " + clock(total)
					}
					fmt.Println(line)
				}
			}
		case line := <-lines:
			if err := playCommand(h, line, state); err != nil {
				if errors.Is(err, errQuit) {
					stop(0)
				}
				fmt.Println(err)
			}
		}
	}
}

var errQuit = errors.New("quit")

// playCommand runs one line of the remote.
func playCommand(h *host, line, state string) error {
	f := strings.Fields(line)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	arg := func(def float64, parse func(string) (float64, error)) (float64, error) {
		if len(f) < 2 {
			return def, nil
		}
		return parse(f[1])
	}
	secs := func(s string) (float64, error) { return strconv.ParseFloat(s, 64) }
	switch {
	case len(f) == 0 || f[0] == "p":
		if state == "PAUSED" {
			return h.control(ctx, "play", 0)
		}
		return h.control(ctx, "pause", 0)
	case f[0] == "f" || f[0] == "b":
		def, sign := 30.0, 1.0
		if f[0] == "b" {
			def, sign = 10, -1
		}
		v, err := arg(def, secs)
		if err != nil || v < 0 {
			return errors.New("seconds, please: f 60")
		}
		return h.control(ctx, "seekBy", sign*v)
	case f[0] == "s":
		v, err := arg(math.NaN(), parseClock)
		if err != nil || math.IsNaN(v) {
			return errors.New("a position, please: s 1:23:45")
		}
		return h.control(ctx, "seek", v)
	case f[0] == "v":
		v, err := arg(math.NaN(), secs)
		if err != nil || math.IsNaN(v) || v < 0 || v > 100 {
			return errors.New("0 to 100, please: v 40")
		}
		return h.control(ctx, "volume", v/100)
	case f[0] == "q":
		return errQuit
	}
	return errors.New(playKeys)
}

// chooseDevice picks the TV: the one -d names, or the one the user picks from
// the list. It never picks by itself, not even when there is only one: a video
// should not start on a TV nobody chose.
func chooseDevice(devs []Device, want string, in io.Reader, out io.Writer) (Device, error) {
	if len(devs) == 0 {
		return Device{}, errors.New("no TV found on this network (is this computer on the same network, and is local network access allowed for your terminal?)")
	}
	if want != "" {
		var hits []Device
		for _, d := range devs {
			if d.Host == want || strings.Contains(strings.ToLower(d.Name), strings.ToLower(want)) {
				hits = append(hits, d)
			}
		}
		if len(hits) == 1 {
			return hits[0], nil
		}
		if len(hits) == 0 {
			fmt.Fprintf(out, "No TV matches %q. Found:\n", want)
		} else {
			fmt.Fprintf(out, "%q matches more than one TV:\n", want)
			devs = hits
		}
		listDevices(out, devs)
		return Device{}, errors.New("name the TV more exactly with -d, or leave -d out to pick from the list")
	}
	listDevices(out, devs)
	sc := bufio.NewScanner(in)
	for tries := 0; tries < 3; tries++ {
		fmt.Fprintf(out, "Cast to [1-%d, Enter for 1, q to quit]: ", len(devs))
		if !sc.Scan() {
			break
		}
		t := strings.TrimSpace(sc.Text())
		if t == "q" {
			return Device{}, errors.New("nothing cast")
		}
		if t == "" {
			return devs[0], nil
		}
		if n, err := strconv.Atoi(t); err == nil && n >= 1 && n <= len(devs) {
			return devs[n-1], nil
		}
	}
	return Device{}, errors.New("no TV picked; nothing cast")
}

func listDevices(out io.Writer, devs []Device) {
	for i, d := range devs {
		note := "new: its identity is remembered when you cast to it"
		if d.Known {
			note = "used before"
		}
		fmt.Fprintf(out, "  %d  %-26s %-22s %-15s %s\n", i+1, d.Name, d.Model, d.Host, note)
	}
}

// parseClock reads 1:23:45, 23:45 or plain seconds.
func parseClock(s string) (float64, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) > 3 {
		return 0, errors.New("not a time")
	}
	total := 0.0
	for _, p := range parts {
		v, err := strconv.ParseFloat(p, 64)
		if err != nil || v < 0 || math.IsInf(v, 0) || math.IsNaN(v) {
			return 0, errors.New("not a time")
		}
		total = total*60 + v
	}
	return total, nil
}

func clock(t float64) string {
	s := int(t)
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}
