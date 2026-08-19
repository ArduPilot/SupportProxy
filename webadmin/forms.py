"""Flask-WTF forms. CSRF tokens are added automatically by FlaskForm.

Every field that is not self-explanatory carries a `description`. The
templates render it as a hover/focus tooltip next to the label (see
_macros.html and the .help rules in style.css), which keeps the labels
short enough to scan while the detail stays one hover away. Put the
explanation in `description`, not in the label.
"""
import keydb_lib

from flask_wtf import FlaskForm
from wtforms import (BooleanField, FloatField, IntegerField, PasswordField,
                     SelectField, StringField, SubmitField)
from wtforms.validators import (DataRequired, Length, NumberRange, Optional,
                                EqualTo)


# Owner cap on log retention (shared by .tlog and .bin files).
# Anything higher requires admin.
OWNER_MAX_LOG_RETENTION_DAYS = 30.0
ADMIN_MAX_LOG_RETENTION_DAYS = 36500.0  # ~100 years; effectively unbounded

# Render-kwargs for "this is a brand-new passphrase, browser, don't
# autofill the user's saved login passphrase here". Without this Chrome
# happily prefills the 'New passphrase' field with the value it has
# stored for /login on this site.
_NEW_PW_KW = {'autocomplete': 'new-password', 'spellcheck': 'false',
              'autocorrect': 'off', 'autocapitalize': 'off'}
_CURRENT_PW_KW = {'autocomplete': 'current-password', 'spellcheck': 'false',
                  'autocorrect': 'off', 'autocapitalize': 'off'}


# Video ports are allocated by an admin, like port1 -- they share one
# global listening-port namespace, so letting every owner pick their own
# invites collisions and squatting. Owners control everything else about
# their video.
VIDEO_PORT_MIN = 1024
VIDEO_PORT_MAX = 65535
VIDEO_MAX_GRACE_S = 3600


# Help text shared by the owner and admin edit forms, so the two copies
# of each field cannot drift apart.
_D_BIDI = ('Normally only the engineer side must sign. With this set the '
           'proxy also requires MAVLink2 signing on the user side, using '
           'the same passphrase, and drops packets that are unsigned or '
           'signed with the wrong key. A session already running keeps '
           'the old setting until it idles out.')
_D_TLOG = ('Write a .tlog of the MAVLink stream to '
           'logs/<port2>/<date>/. Browse and download them from the '
           '"browse logs" link below.')
_D_BINLOG = ('Pull the flight controller\'s dataflash .bin log over the '
             'MAVLink link. The firmware must have the MAVLink bit set '
             'in its LOG_BACKEND_TYPE parameter or nothing arrives.')
_D_RETENTION = ('The cleanup pass deletes .tlog and .bin files older than '
                'this. 0 keeps them forever. Fractional days are allowed. '
                'Video recordings are covered by their own disk budget, '
                'not by this.')
_D_SYSID = ('Restricts flight-controller reboot detection -- which is what '
            'starts a new .bin file -- to packets from this MAVLink system '
            'ID. 0 accepts any sysid, which is usually right unless several '
            'vehicles share one link.')
_D_USE_TZ = ('By default log files are named in the server\'s local time. '
             'Tick this to name them in the fixed offset set below instead, '
             'so filenames match the timezone you fly in.')
_D_TZ_OFFSET = ('Hours ahead of GMT, fractional allowed (e.g. 9.5 for '
                'ACST, -7 for PDT). Only has any effect while the box '
                'above is ticked.')
_D_RESET_TS = ('Zero the stored MAVLink signing timestamp. Use this when '
               'signed packets are being rejected as replays because the '
               'stored timestamp has got ahead of the engineer\'s clock.')
_D_NEW_PASS = ('Sets the shared MAVLink signing passphrase. Leave blank to '
               'keep the current one. Everyone connecting to this entry '
               'must use the new value, so tell them before you save.')


class _VideoOwnerFields:
    """Video settings an owner may change. Ports are admin-only."""
    video_enabled = BooleanField(
        'Enable video proxying for this entry',
        description='Binds this entry\'s video ports and accepts a '
                    'publisher on them. Video runs independently of '
                    'MAVLink: it survives a telemetry dropout, and with a '
                    'publish password it needs no MAVLink session at all.')
    video_audio = BooleanField(
        'Carry audio',
        description='RTSP sources only. Off by default -- aircraft audio '
                    'is rarely useful, and dropping it keeps the stream '
                    'video-only and slightly cheaper to relay.')
    video_viewer_pass = PasswordField(
        'Viewer password',
        description='Required to watch the stream. Leave blank to keep the '
                    'current one; tick the box below to remove it and let '
                    'anyone who can reach the port watch.',
        validators=[Optional(), Length(min=4, max=256)],
        render_kw=_NEW_PW_KW)
    video_viewer_pass_clear = BooleanField(
        'Clear the viewer password',
        description='Removes it entirely, so viewing is open to anyone who '
                    'can reach the video port.')
    video_publish_pass = PasswordField(
        'Publish password',
        description='Lets a publisher in on the password alone, with no '
                    'MAVLink session needed -- the answer for CGNAT, or '
                    'video egressing from a different address than '
                    'telemetry. Note it REPLACES the address check, and '
                    'plain MPEG-TS over UDP cannot carry a password, so '
                    'setting one means publishing over RTSP.',
        validators=[Optional(), Length(min=4, max=256)],
        render_kw=_NEW_PW_KW)
    video_publish_pass_clear = BooleanField(
        'Clear the publish password',
        description='Publishing then requires a recent MAVLink session '
                    'from the same IP address instead.')
    video_grace_s = IntegerField(
        'Publisher grace after MAVLink drops (seconds)',
        description='How long a passwordless publisher stays authorised '
                    'after its MAVLink session goes away, so video rides '
                    'through a telemetry outage instead of being cut by a '
                    'link flap. 0 uses the default of %d seconds.' % 60,
        validators=[Optional(), NumberRange(min=0, max=VIDEO_MAX_GRACE_S)])
    # Per-slot options. Flat fields rather than a FieldList to match the
    # rest of this module and keep the templates simple.
    # RTMP publish path per slot. Owner-settable like the other
    # per-slot options: it describes what the camera is configured to
    # send, not an allocation the admin controls.
    video_rtmp_1 = StringField(
        'Slot 1 RTMP path',
        description='Optional. The App Name and Stream ID set on the '
                    'camera, as "app/stream" -- e.g. PhoenixFPV/FPV. Set, '
                    'only that path is accepted on this slot; left blank '
                    'the slot takes whatever the camera publishes.',
        validators=[Optional(), Length(max=31)])
    video_rtmp_2 = StringField(
        'Slot 2 RTMP path',
        description='As above, for the second slot.',
        validators=[Optional(), Length(max=31)])
    video_rtmp_3 = StringField(
        'Slot 3 RTMP path',
        description='As above, for the third slot.',
        validators=[Optional(), Length(max=31)])
    video_rtmp_4 = StringField(
        'Slot 4 RTMP path',
        description='As above, for the fourth slot.',
        validators=[Optional(), Length(max=31)])
    video_rtmp_5 = StringField(
        'Slot 5 RTMP path',
        description='As above, for the fifth slot.',
        validators=[Optional(), Length(max=31)])
    video_srt_1 = BooleanField('Slot 1: UDP side speaks SRT (else MPEG-TS)')
    video_record_1 = BooleanField('Slot 1: record to disk')
    video_rawtcp_1 = BooleanField('Slot 1: allow raw-TCP viewers (no password)')
    video_sessok_1 = BooleanField(
        'Slot 1: publish with no password when the MAVLink session matches')
    video_srt_2 = BooleanField('Slot 2: UDP side speaks SRT (else MPEG-TS)')
    video_record_2 = BooleanField('Slot 2: record to disk')
    video_rawtcp_2 = BooleanField('Slot 2: allow raw-TCP viewers (no password)')
    video_sessok_2 = BooleanField(
        'Slot 2: publish with no password when the MAVLink session matches')
    video_srt_3 = BooleanField('Slot 3: UDP side speaks SRT (else MPEG-TS)')
    video_record_3 = BooleanField('Slot 3: record to disk')
    video_rawtcp_3 = BooleanField('Slot 3: allow raw-TCP viewers (no password)')
    video_sessok_3 = BooleanField(
        'Slot 3: publish with no password when the MAVLink session matches')
    video_srt_4 = BooleanField('Slot 4: UDP side speaks SRT (else MPEG-TS)')
    video_record_4 = BooleanField('Slot 4: record to disk')
    video_rawtcp_4 = BooleanField('Slot 4: allow raw-TCP viewers (no password)')
    video_sessok_4 = BooleanField(
        'Slot 4: publish with no password when the MAVLink session matches')
    video_srt_5 = BooleanField('Slot 5: UDP side speaks SRT (else MPEG-TS)')
    video_record_5 = BooleanField('Slot 5: record to disk')
    video_rawtcp_5 = BooleanField('Slot 5: allow raw-TCP viewers (no password)')
    video_sessok_5 = BooleanField(
        'Slot 5: publish with no password when the MAVLink session matches')


class _VideoAdminFields(_VideoOwnerFields):
    """Adds the port allocation and the disk budget."""
    # How many slots this entry uses. Most entries want one camera, so
    # showing every set of ports and per-slot options by default is
    # noise; this drives which slots the page shows at all.
    video_port_count = SelectField(
        'Number of video ports',
        description='One port carries one stream, so allocate one per '
                    'camera. Slots you do not use are hidden.',
        choices=[(n, str(n))
                 for n in range(1, keydb_lib.MAX_VIDEO_PORTS + 1)],
        coerce=int, default=1)
    video_port_1 = IntegerField(
        'Video port 1',
        description='Publish to this port and viewers connect to it. '
                    'Suggested value is the next free port; it must not '
                    'clash with any other entry\'s ports.',
        validators=[Optional(), NumberRange(min=VIDEO_PORT_MIN,
                                            max=VIDEO_PORT_MAX)])
    video_port_2 = IntegerField(
        'Video port 2',
        description='Second camera. One port carries exactly one stream.',
        validators=[Optional(), NumberRange(min=VIDEO_PORT_MIN,
                                            max=VIDEO_PORT_MAX)])
    video_port_3 = IntegerField(
        'Video port 3',
        description='Third camera. One port carries exactly one stream.',
        validators=[Optional(), NumberRange(min=VIDEO_PORT_MIN,
                                            max=VIDEO_PORT_MAX)])
    video_port_4 = IntegerField(
        'Video port 4',
        description='Fourth camera. One port carries exactly one stream.',
        validators=[Optional(), NumberRange(min=VIDEO_PORT_MIN,
                                            max=VIDEO_PORT_MAX)])
    video_port_5 = IntegerField(
        'Video port 5',
        description='Fifth camera. One port carries exactly one stream.',
        validators=[Optional(), NumberRange(min=VIDEO_PORT_MIN,
                                            max=VIDEO_PORT_MAX)])
    video_quota_mb = IntegerField(
        'Video disk budget (MB)',
        description='Oldest recordings are deleted once this entry\'s '
                    'video exceeds the budget. Kept separate from the '
                    'tlog/bin budget so video can never evict telemetry. '
                    '0 uses the server default.',
        validators=[Optional(), NumberRange(min=0)])


class LoginForm(FlaskForm):
    port = IntegerField(
        'Port (port1 or port2)',
        description='Either side of your pair works. Log in on port2 and '
                    'you get the engineer view; either way you reach the '
                    'same entry.',
        validators=[DataRequired(), NumberRange(min=1, max=65535)])
    # No description, so no tooltip: pasting into this field with the
    # tooltip up wedges Chrome's renderer hard enough that the tab stops
    # responding to input entirely. The text it carried is in the blurb
    # above the form instead, where it costs nothing.
    passphrase = PasswordField(
        'Passphrase',
        validators=[DataRequired(), Length(min=1, max=256)],
        render_kw=_CURRENT_PW_KW)
    submit = SubmitField('Log in')


class OwnerEditForm(FlaskForm, _VideoOwnerFields):
    """Self-service form: name + optional new passphrase + flag toggles."""
    name = StringField(
        'Display name',
        description='Free-text label shown in the entry list and the '
                    'connections page. Cosmetic only.',
        validators=[Optional(), Length(max=31)])
    new_passphrase = PasswordField(
        'New passphrase (leave blank to keep current)',
        description=_D_NEW_PASS,
        validators=[Optional(), Length(min=4, max=256)],
        render_kw=_NEW_PW_KW)
    confirm_passphrase = PasswordField(
        'Confirm new passphrase',
        description='Must match the field above. Guards against a typo '
                    'locking everyone out of the entry.',
        validators=[Optional(), EqualTo('new_passphrase',
                                        message='Passphrases do not match.')],
        render_kw=_NEW_PW_KW)
    bidi_sign = BooleanField(
        'Require MAVLink signing on the user side too (bi-directional '
        'signing)', description=_D_BIDI)
    tlog_enabled = BooleanField('Record telemetry logs (.tlog)',
                                description=_D_TLOG)
    binlog_enabled = BooleanField('Record ArduPilot bin logs (.bin)',
                                  description=_D_BINLOG)
    log_retention_days = FloatField(
        'Log retention (days, 0 = keep forever)',
        description=_D_RETENTION + ' Owners are capped at %d days; ask an '
                    'admin for longer.' % OWNER_MAX_LOG_RETENTION_DAYS,
        validators=[Optional(),
                    NumberRange(min=0.0, max=OWNER_MAX_LOG_RETENTION_DAYS)])
    fc_sysid = IntegerField(
        'Flight-controller MAVLink sysid (0 = any)', description=_D_SYSID,
        validators=[Optional(), NumberRange(min=0, max=255)])
    use_tz = BooleanField('Name logs in a fixed timezone',
                          description=_D_USE_TZ)
    tz_offset_hours = FloatField(
        'Log timezone (GMT offset in hours)', description=_D_TZ_OFFSET,
        validators=[Optional(), NumberRange(min=-12.0, max=14.0)])
    reset_timestamp = BooleanField('Reset signing timestamp',
                                   description=_D_RESET_TS)
    submit = SubmitField('Save')


class AdminEditForm(FlaskForm, _VideoAdminFields):
    """Admin form: same as owner plus port1, video ports and admin flag."""
    name = StringField(
        'Display name',
        description='Free-text label shown in the entry list and the '
                    'connections page. Cosmetic only.',
        validators=[Optional(), Length(max=31)])
    port1 = IntegerField(
        'User-side port (port1)',
        description='The port the aircraft or ground station connects to. '
                    'Changing it re-binds the listener within about 5 '
                    'seconds and drops any session on the old port.',
        validators=[DataRequired(), NumberRange(min=1, max=65535)])
    new_passphrase = PasswordField(
        'New passphrase (leave blank to keep current)',
        description=_D_NEW_PASS,
        validators=[Optional(), Length(min=4, max=256)],
        render_kw=_NEW_PW_KW)
    confirm_passphrase = PasswordField(
        'Confirm new passphrase',
        description='Must match the field above. Guards against a typo '
                    'locking everyone out of the entry.',
        validators=[Optional(), EqualTo('new_passphrase',
                                        message='Passphrases do not match.')],
        render_kw=_NEW_PW_KW)
    is_admin = BooleanField(
        'Grant admin privilege (KEY_FLAG_ADMIN)',
        description='Lets whoever holds this entry\'s passphrase view and '
                    'edit every entry on the server, not just their own.')
    bidi_sign = BooleanField(
        'Require MAVLink signing on the user side too (bi-directional '
        'signing)', description=_D_BIDI)
    tlog_enabled = BooleanField('Record telemetry logs (.tlog)',
                                description=_D_TLOG)
    binlog_enabled = BooleanField('Record ArduPilot bin logs (.bin)',
                                  description=_D_BINLOG)
    log_retention_days = FloatField(
        'Log retention (days, 0 = keep forever)', description=_D_RETENTION,
        validators=[Optional(),
                    NumberRange(min=0.0, max=ADMIN_MAX_LOG_RETENTION_DAYS)])
    fc_sysid = IntegerField(
        'Flight-controller MAVLink sysid (0 = any)', description=_D_SYSID,
        validators=[Optional(), NumberRange(min=0, max=255)])
    use_tz = BooleanField('Name logs in a fixed timezone',
                          description=_D_USE_TZ)
    tz_offset_hours = FloatField(
        'Log timezone (GMT offset in hours)', description=_D_TZ_OFFSET,
        validators=[Optional(), NumberRange(min=-12.0, max=14.0)])
    reset_timestamp = BooleanField('Reset signing timestamp',
                                   description=_D_RESET_TS)
    submit = SubmitField('Save')


# Cap on how many consecutive IDs one "Add" can create. Generous
# enough for any real partner onboarding, small enough that the
# port1..port1+count-1 and port2..port2+count-1 ranges can never
# collide with each other (they're 1000 apart).
MAX_ADD_COUNT = 50


class AdminAddForm(FlaskForm):
    # Port range matches SupportProxy convention: pick from the
    # 10000–60000 range to stay clear of well-known ports and most
    # ephemeral allocations. port1 / port2 uniqueness across the
    # database is enforced by keydb_lib.add_entry().
    #
    # port1 is the *base* user-side port. With count == 1 the explicit
    # port2 field is used; with count > 1 the route derives, for
    # entry i (1-indexed): port1 = base + i - 1, port2 = port1 + 1000,
    # name = "<name><i>", all sharing one passphrase — matching the
    # old add_partner.sh script.
    port1 = IntegerField(
        'User-side base port (port1)',
        description='The port the aircraft or ground station connects to. '
                    'With count > 1 this is the first of a consecutive run.',
        validators=[DataRequired(), NumberRange(min=10000, max=60000)])
    count = IntegerField(
        'Count (consecutive IDs to create)',
        description='Create this many entries in one go: port1 counts up '
                    'from the base, port2 is port1+1000 for each, and the '
                    'display name gets an index suffix. All share one '
                    'passphrase.',
        default=1,
        validators=[Optional(), NumberRange(min=1, max=MAX_ADD_COUNT)])
    port2 = IntegerField(
        'Engineer-side port (port2)',
        description='The port the support engineer connects to. Always '
                    'requires MAVLink2 signing. Used only when count = 1; '
                    'otherwise it is derived as port1+1000.',
        validators=[DataRequired(), NumberRange(min=10000, max=60000)])
    name = StringField(
        'Display name',
        description='Free-text label for the entry list. With count > 1 '
                    'each entry gets a number appended.',
        validators=[DataRequired(), Length(max=31)])
    passphrase = PasswordField(
        'Passphrase',
        description='The shared MAVLink signing passphrase, and what both '
                    'sides use to log in here. Use "Generate" for a strong '
                    'one.',
        validators=[DataRequired(), Length(min=4, max=256)],
        render_kw=_NEW_PW_KW)
    submit = SubmitField('Add')


class DeleteForm(FlaskForm):
    """Empty form just to carry a CSRF token for the delete button."""
    submit = SubmitField('Delete')


class KillForm(FlaskForm):
    """Empty form just to carry a CSRF token for the kill-connection button."""
    submit = SubmitField('Kill')


class RestartProxyForm(FlaskForm):
    """CSRF carrier for the restart-daemon button.

    Deliberately its own form rather than reusing KillForm: this one
    drops every live session on the server, so a stray token from
    another page should not be able to trigger it.
    """
    submit = SubmitField('Restart proxy')


class DeleteLogForm(FlaskForm):
    """CSRF carrier for deleting a recording, or a whole day of them."""
    submit = SubmitField('Delete')
