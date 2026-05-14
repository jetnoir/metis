#!/bin/sh
# dtrace_run.sh <image_path>
# Runs imageio_harness under DTrace, outputs function hit counts to stdout
IMAGE="$1"
if [ -z "$IMAGE" ]; then echo "Usage: $0 <image>"; exit 1; fi

exec dtrace -n '
pid$target::*CGImageSource*:entry,
pid$target::*IIO_Reader*:entry,
pid$target::*IIOImage*:entry,
pid$target::*PNGRead*:entry,
pid$target::*_cg_png*:entry,
pid$target::*CGImage*:entry,
pid$target::*png_*:entry,
pid$target::*TIFF*:entry,
pid$target::*Tiff*:entry,
pid$target::*HEIF*:entry,
pid$target::*Exif*:entry,
pid$target::*ICC*:entry,
pid$target::*RawCamera*:entry
{ @[probefunc] = count(); }
' -c "/tmp/imageio_harness $IMAGE" 2>/dev/null
