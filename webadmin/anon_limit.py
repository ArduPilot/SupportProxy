"""One budget of worker threads for everything served without a login.

The shipped gunicorn runs 4 threads. Anonymous work that holds a thread
for as long as a client reads (public log playback, HLS for bystanders)
draws from this single budget, so together they leave one thread for the
login page and the admin UI. Separate caps would add up past that.
"""
import threading

MAX = 3
slots = threading.BoundedSemaphore(MAX)
