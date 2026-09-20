package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// A DASH manifest is bytes a web server chose. Whatever they are, the
// rewriter must return, and what it lets through must still be XML: it
// splices the input by the tokenizer's offsets, and a slip there would hand
// the TV a manifest that says something the rewriter never saw.
//
//	go test -run='^$' -fuzz='^FuzzRewriteMPD$' -fuzztime=30s .
func FuzzRewriteMPD(f *testing.F) {
	for _, s := range []string{
		"",
		`<MPD><BaseURL>https://cdn.example/a/b/</BaseURL><Period><BaseURL>video/</BaseURL></Period></MPD>`,
		"<MPD>\r\n<BaseURL serviceLocation=\"a\">\r\n  https://cdn.example/a/b/manifest.mpd?x=1&amp;y=2  \r\n</BaseURL>\r\n</MPD>",
		`<MPD xmlns:xlink="http://www.w3.org/1999/xlink"><Location>https://site.example/m.mpd</Location><Period xlink:href="https://site.example/p.xml"/></MPD>`,
		`<MPD><Period><SegmentTemplate media="https://cdn.example/x/$RepresentationID$/$Number$.m4s?t=1" initialization='//cdn.example/x/init.mp4'/></Period></MPD>`,
		`<MPD><UTCTiming schemeIdUri="urn:mpeg:dash:utc:http-xsdate:2014" value="https://time.example/?iso"/><Period/></MPD>`,
		`<MPD><BaseURL>&#104;ttp://cdn.example/&#0;&#x110000;&bogus;/%zz/</BaseURL></MPD>`,
		`<MPD><BaseURL attr="https://cdn.example/a/</BaseURL>`,
		`<MPD><BaseURL><![CDATA[https://cdn.example/a/]]>b/</BaseURL><!-- c --><?pi x?></MPD>`,
		"\ufeff<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><MPD><BaseURL>http://cdn.example/\xff\xfe\x80/</BaseURL></MPD>",
		`<MPD><Location><a><Location>x</Location></a></Location><Period/></MPD>`,
		"<MPD>" + strings.Repeat("<BaseURL>http://h/</BaseURL>", 500) + "</MPD>",
	} {
		f.Add([]byte(s), true)
	}
	p := &proxy{base: "http://proxy", sessions: map[string]*session{}}
	s, err := p.newSession(nil, netip.MustParseAddr("192.168.1.2"))
	if err != nil {
		f.Fatal(err)
	}
	base, _ := url.Parse("https://site.example/vod/42/manifest.mpd?sig=1")
	file := func(u *url.URL) string { return p.fileURL(s, u.String()) }
	dir := func(u *url.URL) (string, bool) { return p.dirURL(s, u) }
	f.Fuzz(func(t *testing.T, src []byte, strict bool) {
		if len(src) > 1<<16 {
			t.Skip()
		}
		out := rewriteMPD(src, base, strict, file, dir)
		if out == nil {
			return
		}
		if len(out) > maxRewritten {
			t.Fatalf("%d bytes out, over the cap", len(out))
		}
		dec := xml.NewDecoder(bytes.NewReader(out))
		dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
		for {
			if _, err := dec.RawToken(); err == io.EOF {
				break
			} else if err != nil {
				t.Fatalf("let through, but no longer XML: %v\nin:  %q\nout: %q", err, src, out)
			}
		}
	})
}
