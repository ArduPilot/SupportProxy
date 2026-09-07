"""Shared glue between the video form fields and a KeyEntry.

The owner and admin edit routes present the same video settings (the
admin form adds port allocation and the disk budget), so the populate
and apply logic lives here rather than being written twice.
"""
import keydb_lib

# Per-slot form field prefixes -> the bit they map to.
_SLOT_FIELDS = (
    ('video_srt_%d', keydb_lib.VIDEO_SLOT_SRT),
    ('video_record_%d', keydb_lib.VIDEO_SLOT_RECORD),
    ('video_rawtcp_%d', keydb_lib.VIDEO_SLOT_RAW_TCP),
    ('video_sessok_%d', keydb_lib.VIDEO_SLOT_SESSION_OK),
    ('video_openpub_%d', keydb_lib.VIDEO_SLOT_OPEN_PUB),
)


def populate(form, ke, db=None):
    """Fill the video fields of `form` from `ke` (GET path).

    `db` enables suggesting the next free port for unallocated slots.
    """
    form.video_enabled.data = ke.video_enabled()
    form.video_audio.data = bool(
        keydb_lib.video_entry_opts(ke.video_flags) & keydb_lib.VIDEO_OPT_AUDIO)
    form.video_grace_s.data = ke.video_mav_grace_s

    for slot in range(keydb_lib.MAX_VIDEO_PORTS):
        opts = ke.slot_opts(slot)
        for name_fmt, bit in _SLOT_FIELDS:
            getattr(form, name_fmt % (slot + 1)).data = bool(opts & bit)
        getattr(form, 'video_rtmp_%d' % (slot + 1)).data = ke.rtmp_path(slot)

    # Admin-only fields.
    if hasattr(form, 'video_port_1'):
        form.video_port_count.data = ke.video_port_count()
        # Suggest a port for every slot, not just the ones in use, so
        # raising the count reveals a filled-in field instead of a blank
        # one the admin has to research a free port for. Slots past the
        # count are not saved (see apply), so an unused suggestion costs
        # nothing.
        if db is not None:
            ports = keydb_lib.suggest_video_ports(
                db, ke, keydb_lib.MAX_VIDEO_PORTS, keep=ke.video_ports)
        else:
            ports = list(ke.video_ports[:keydb_lib.MAX_VIDEO_PORTS])
        for slot in range(keydb_lib.MAX_VIDEO_PORTS):
            getattr(form, 'video_port_%d' % (slot + 1)).data = (
                ports[slot] or None)
    if hasattr(form, 'video_quota_mb'):
        form.video_quota_mb.data = ke.video_quota_mb

    # Password fields are never populated -- blank means "keep current".


def apply(form, ke, db):
    """Apply the video fields of `form` onto `ke` (POST path).

    Returns an error string to flash, or None on success. `ke` is
    mutated in place; the caller stores it.
    """
    if form.video_enabled.data:
        ke.flags |= keydb_lib.FLAG_VIDEO
    else:
        ke.flags &= ~keydb_lib.FLAG_VIDEO

    opts = keydb_lib.video_entry_opts(ke.video_flags)
    if form.video_audio.data:
        opts |= keydb_lib.VIDEO_OPT_AUDIO
    else:
        opts &= ~keydb_lib.VIDEO_OPT_AUDIO
    ke.video_flags = keydb_lib.video_set_entry_opts(ke.video_flags, opts)

    for slot in range(keydb_lib.MAX_VIDEO_PORTS):
        slot_opts = ke.slot_opts(slot)
        for name_fmt, bit in _SLOT_FIELDS:
            if getattr(form, name_fmt % (slot + 1)).data:
                slot_opts |= bit
            else:
                slot_opts &= ~bit
        ke.set_slot_opts(slot, slot_opts)
        try:
            ke.set_rtmp_path(
                slot, getattr(form, 'video_rtmp_%d' % (slot + 1)).data or '')
        except keydb_lib.CLIError as e:
            return 'Slot %d RTMP path: %s' % (slot + 1, e)

    ke.video_mav_grace_s = int(form.video_grace_s.data or 0)

    # Ports: admin-only. Validate against the whole DB before storing.
    #
    # Only touched while video is enabled. The page suggests a port for
    # every slot, so writing them unconditionally would allocate ports
    # to an entry that has video off just because someone saved an
    # unrelated field on the same form.
    if hasattr(form, 'video_port_1') and form.video_enabled.data:
        # A submission that carries no count at all predates the
        # selector; take every slot rather than silently dropping slot 2
        # and 3 onto the field's default of 1.
        count = keydb_lib.MAX_VIDEO_PORTS
        if form.video_port_count.raw_data:
            count = int(form.video_port_count.data or 1)
        wanted = [getattr(form, 'video_port_%d' % (i + 1)).data or 0
                  if i < count else 0
                  for i in range(keydb_lib.MAX_VIDEO_PORTS)]
        try:
            ke.video_ports = keydb_lib.validate_video_ports(db, ke, wanted)
        except keydb_lib.CLIError as e:
            return str(e)
    if hasattr(form, 'video_quota_mb'):
        ke.video_quota_mb = int(form.video_quota_mb.data or 0)

    # Passwords: blank keeps the current value, the paired checkbox clears
    # it. Setting and clearing at once is a contradiction, so reject it
    # rather than silently picking one.
    for field, clear_field, setter, label in (
            (form.video_viewer_pass, form.video_viewer_pass_clear,
             ke.set_video_viewer_pass, 'viewer'),
            (form.video_publish_pass, form.video_publish_pass_clear,
             ke.set_video_publish_pass, 'publish')):
        if field.data and clear_field.data:
            return ('Cannot both set and clear the video %s password.' % label)
        if clear_field.data:
            setter('')
        elif field.data:
            setter(field.data)

    return None
