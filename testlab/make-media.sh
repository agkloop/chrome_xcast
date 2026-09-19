#!/bin/sh
# Generates the lab's synthetic test videos (a test pattern with a running
# clock and a tone). Needs ffmpeg. Nothing is downloaded.
set -eu
cd "$(dirname "$0")"
mkdir -p hls v2

ffmpeg -hide_banner -loglevel error -y \
  -f lavfi -i "testsrc2=size=1280x720:rate=30" -f lavfi -i "sine=frequency=440:sample_rate=48000" -t 120 \
  -vf "drawtext=text='XCast test lab  %{pts\:hms}':fontsize=48:fontcolor=white:box=1:boxcolor=black@0.6:x=40:y=40" \
  -c:v libx264 -profile:v high -level 4.0 -pix_fmt yuv420p -g 120 -keyint_min 120 -sc_threshold 0 -b:v 2500k \
  -c:a aac -b:a 128k -ac 2 \
  -f hls -hls_time 4 -hls_playlist_type vod -hls_segment_filename "hls/seg_%03d.ts" hls/stream.m3u8

ffmpeg -hide_banner -loglevel error -y \
  -f lavfi -i "testsrc2=size=1280x720:rate=30" -f lavfi -i "sine=frequency=660:sample_rate=48000" -t 90 \
  -vf "drawtext=text='XCast lab 3 MP4  %{pts\:hms}':fontsize=48:fontcolor=white:box=1:boxcolor=black@0.6:x=40:y=40" \
  -c:v libx264 -profile:v high -level 4.0 -pix_fmt yuv420p -b:v 2500k -c:a aac -b:a 128k -ac 2 \
  -movflags +faststart v2/7k9labvideo.mp4

echo "Test media ready. Start the lab with: python3 server.py"
