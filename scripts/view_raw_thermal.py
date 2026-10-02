#!/usr/bin/env python3
"""View lossless APCG thermal Matroska from SupportProxy or a local camera.

Requires the MAVProxy raw thermal reader, PyAV >= 18.1, numpy and OpenCV.
Space pauses; C cycles greyscale/inferno/turbo; S saves native pixels and JSON.
"""
import argparse
import json
from pathlib import Path
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('uri')
    parser.add_argument('--mavproxy', type=Path, help='MAVProxy checkout containing the raw thermal reader')
    parser.add_argument('--output', type=Path, default=Path('thermal-captures'))
    parser.add_argument('--headless', action='store_true', help='validate decoded frames without opening a window')
    parser.add_argument('--frames', type=int, default=0, help='exit after this many received frames (0: unlimited)')
    args = parser.parse_args()
    if args.frames < 0:
        parser.error('--frames must be nonnegative')
    if args.mavproxy:
        sys.path.insert(0, str(args.mavproxy.resolve()))
    import numpy as np
    from MAVProxy.modules.mavproxy_camera.thermal_stream import ThermalReader
    if not args.headless:
        import cv2
    stop = threading.Event()
    lock = threading.Lock()
    latest, error, count = None, None, 0

    def receive():
        nonlocal latest, error, count
        while not stop.is_set():
            reader = None
            try:
                reader = ThermalReader(args.uri)
                for pixels, metadata in reader.frames():
                    with lock:
                        latest = pixels, metadata
                        error = None
                        count += 1
                    if stop.is_set() or (args.frames and count >= args.frames):
                        return
                raise RuntimeError('stream ended')
            except Exception as exc:
                # Exception URLs can contain the viewer password.
                with lock:
                    error = 'Stream unavailable (%s); reconnecting' % type(exc).__name__
            finally:
                if reader:
                    reader.close()
            stop.wait(1)

    worker = threading.Thread(target=receive, daemon=True)
    worker.start()
    shown = None
    cursor = None
    paused, palette = False, 0
    window = 'Raw Thermal'
    if not args.headless:
        cv2.namedWindow(window, cv2.WINDOW_AUTOSIZE)
        def mouse(_event, x, y, _flags, _data):
            nonlocal cursor
            cursor = (x, y) if 0 <= x < 640 and 0 <= y < 512 else None
        cv2.setMouseCallback(window, mouse)
    try:
        while True:
            with lock:
                frame, status, received = latest, error, count
            if not paused and frame is not None:
                shown = frame
            if args.headless:
                if args.frames and received >= args.frames:
                    print('Decoded %u native 16-bit frames with metadata' % received)
                    break
                time.sleep(.02)
                continue
            if shown is not None:
                pixels, metadata = shown
                lo, hi = int(pixels.min()), int(pixels.max())
                grey = ((pixels.astype(np.float32)-lo)*(255/max(1, hi-lo))).astype(np.uint8)
                if metadata['rotation_deg'] == 180:
                    grey = grey[::-1, ::-1]
                display = cv2.cvtColor(grey, cv2.COLOR_GRAY2BGR) if palette == 0 else cv2.applyColorMap(
                    grey, (cv2.COLORMAP_INFERNO, cv2.COLORMAP_TURBO)[palette-1])
                display = cv2.copyMakeBorder(display, 0, 68, 0, 0, cv2.BORDER_CONSTANT)
                text = 'Min %.2f C   Max %.2f C%s' % (
                    metadata['minimum_c'], metadata['maximum_c'], '  PAUSED' if paused else '')
                pixel_text = 'Hover for temperature; Space pause, C palette, S save'
                if cursor:
                    x, y = cursor
                    sx, sy = (639-x, 511-y) if metadata['rotation_deg'] == 180 else (x, y)
                    temp = int(pixels[sy, sx])*metadata['temperature_scale_k']+metadata['temperature_offset_k']-273.15
                    pixel_text = 'Pixel (%u,%u): %.3f C' % (x, y, temp)
                cv2.putText(display, text, (8, 536), cv2.FONT_HERSHEY_SIMPLEX, .55, (255,255,255), 1)
                cv2.putText(display, status or pixel_text, (8, 564), cv2.FONT_HERSHEY_SIMPLEX, .5, (255,255,255), 1)
                cv2.imshow(window, display)
            key = cv2.waitKey(20) & 255
            if key in (27, ord('q')) or cv2.getWindowProperty(window, cv2.WND_PROP_VISIBLE) < 1:
                break
            if key == ord(' '): paused = not paused
            if key == ord('c'): palette = (palette+1) % 3
            if key == ord('s') and shown is not None:
                pixels, metadata = shown
                args.output.mkdir(parents=True, exist_ok=True)
                stem = args.output / ('%u_%u' % (metadata['capture_monotonic_us'], metadata['frame_id']))
                with stem.with_suffix('.bin').open('xb') as f:
                    f.write(pixels.astype('<u2', copy=False).tobytes())
                with stem.with_suffix('.json').open('x') as f:
                    json.dump(metadata, f, indent=2)
            if args.frames and received >= args.frames: break
    finally:
        stop.set()
        # PyAV containers are owned and closed by the reader thread. Its
        # bounded network timeout lets shutdown complete without racing decode.
        worker.join(timeout=6)
        if not args.headless: cv2.destroyAllWindows()


if __name__ == '__main__':
    main()
