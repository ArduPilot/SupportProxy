"""Video settings in the owner and admin edit forms.

Video ports are admin-allocated, like port1: they share one global
listening-port namespace, so owners must not be able to pick their own.
Owners control everything else about their video. Both halves are tested
here, along with the password set/clear semantics.
"""
import re

import keydb_lib

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2, BOB_PASS,
                           BOB_PORT1, BOB_PORT2, fetch_entry, login_as)

VPORT_A = 21001
VPORT_B = 21002


def _owner_post(client, **over):
    """Minimal valid owner form; video fields default to off."""
    data = {'name': 'alice', 'submit': 'Save'}
    data.update(over)
    return client.post('/me/', data=data)


def _admin_post(client, port2, **over):
    data = {'name': 'entry', 'port1': ALICE_PORT1, 'submit': 'Save'}
    data.update(over)
    return client.post('/admin/%d' % port2, data=data)


class TestOwnerVideo:
    def test_owner_form_has_no_port_fields(self, client, keydb_path):
        """Ports are admin-only; the owner page must not offer them."""
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/').get_data(as_text=True)
        assert 'Video' in html
        assert 'video_enabled' in html
        assert 'name="video_port_1"' not in html
        assert 'name="video_quota_mb"' not in html

    def test_owner_can_enable_video_and_slot_options(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = _owner_post(client, video_enabled='y', video_record_1='y',
                           video_srt_2='y', video_rawtcp_3='y',
                           video_openpub_4='y',
                           video_audio='y', video_grace_s='120')
        assert resp.status_code == 302

        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_enabled()
        assert ke.slot_opt_names(0) == ['record']
        assert ke.slot_opt_names(1) == ['srt']
        assert ke.slot_opt_names(2) == ['raw_tcp']
        assert ke.slot_opt_names(3) == ['open_publish']
        assert ke.entry_opt_names() == ['audio']
        assert ke.mav_grace_seconds() == 120

    def test_owner_can_disable_video_again(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        _owner_post(client, video_enabled='y', video_record_1='y')
        assert fetch_entry(keydb_path, ALICE_PORT2).video_enabled()

        _owner_post(client)          # everything unchecked
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not ke.video_enabled()
        assert ke.slot_opt_names(0) == []

    def test_owner_cannot_set_ports_by_posting_them(self, client, keydb_path):
        """Posting the admin-only field must not take effect."""
        login_as(client, ALICE_PORT1, ALICE_PASS)
        _owner_post(client, video_enabled='y', video_port_1=str(VPORT_A),
                    video_quota_mb='9999')
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_ports == [0, 0, 0, 0, 0]
        assert ke.video_quota_mb == 0

    def test_owner_grace_out_of_range_rejected(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        resp = _owner_post(client, video_enabled='y', video_grace_s='99999')
        assert resp.status_code == 200          # form re-renders
        assert fetch_entry(keydb_path, ALICE_PORT2).video_mav_grace_s == 0


class TestVideoPasswords:
    def test_set_then_blank_keeps_password(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        _owner_post(client, video_enabled='y', video_viewer_pass='watchme')
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_viewer_pass_matches('watchme')

        # A later save with the field blank must not wipe it.
        _owner_post(client, video_enabled='y')
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_viewer_pass_matches('watchme')

    def test_clear_checkbox_clears(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        _owner_post(client, video_enabled='y', video_viewer_pass='watchme')
        _owner_post(client, video_enabled='y', video_viewer_pass_clear='y')
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not ke.video_viewer_pass_set()
        assert not ke.video_viewer_pass_matches('')

    def test_set_and_clear_together_is_rejected(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        _owner_post(client, video_enabled='y', video_viewer_pass='first')
        resp = _owner_post(client, video_enabled='y',
                           video_viewer_pass='second',
                           video_viewer_pass_clear='y')
        assert resp.status_code == 302
        # contradiction refused; the original password survives
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_viewer_pass_matches('first')

    def test_viewer_and_publish_passwords_independent(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        _owner_post(client, video_enabled='y', video_viewer_pass='viewpw',
                    video_publish_pass='pubpw')
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_viewer_pass_matches('viewpw')
        assert ke.video_publish_pass_matches('pubpw')
        # and neither disturbs the MAVLink passphrase
        assert ke.passphrase_matches(ALICE_PASS)

        _owner_post(client, video_enabled='y', video_viewer_pass_clear='y')
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert not ke.video_viewer_pass_set()
        assert ke.video_publish_pass_matches('pubpw')


class TestAdminVideo:
    def test_admin_can_allocate_ports(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = _admin_post(client, ALICE_PORT2, video_enabled='y',
                           video_port_1=str(VPORT_A),
                           video_port_2=str(VPORT_B),
                           video_quota_mb='4096')
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_ports == [VPORT_A, VPORT_B, 0, 0, 0]
        assert ke.video_quota_mb == 4096
        assert ke.active_video_ports() == [(0, VPORT_A), (1, VPORT_B)]

    def test_admin_video_port_collision_is_refused(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        # take a port that another entry already binds as its port1
        resp = _admin_post(client, ALICE_PORT2, video_enabled='y',
                           video_port_1=str(BOB_PORT1))
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_ports == [0, 0, 0, 0, 0], 'collision must not be stored'

    def test_admin_video_port_cannot_take_own_port2(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        resp = _admin_post(client, ALICE_PORT2, video_enabled='y',
                           video_port_1=str(ALICE_PORT2))
        assert resp.status_code == 302
        assert fetch_entry(keydb_path, ALICE_PORT2).video_ports == [0, 0, 0, 0, 0]

    def test_admin_can_clear_ports(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        _admin_post(client, ALICE_PORT2, video_enabled='y',
                    video_port_1=str(VPORT_A))
        assert fetch_entry(keydb_path, ALICE_PORT2).video_ports[0] == VPORT_A
        _admin_post(client, ALICE_PORT2, video_enabled='y', video_port_1='')
        assert fetch_entry(keydb_path, ALICE_PORT2).video_ports == [0, 0, 0, 0, 0]

    def test_allocated_port_blocks_a_later_port1_change(self, client,
                                                        keydb_path):
        """port1 uniqueness must consider video ports too."""
        login_as(client, BOB_PORT1, BOB_PASS)
        _admin_post(client, ALICE_PORT2, video_enabled='y',
                    video_port_1=str(VPORT_A))
        # now try to move BOB's port1 onto alice's video port
        resp = client.post('/admin/%d' % BOB_PORT2,
                           data={'name': 'bob', 'port1': str(VPORT_A),
                                 'is_admin': 'y', 'submit': 'Save'})
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, BOB_PORT2)
        assert ke.port1 == BOB_PORT1, 'port1 must not take a video port'

    def test_admin_page_shows_video_fields(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        assert 'name="video_port_1"' in html
        assert 'name="video_quota_mb"' in html
        assert 'name="video_record_1"' in html


class TestVideoSlotRendering:
    def _allocate(self, client, keydb_path, ports):
        login_as(client, BOB_PORT1, BOB_PASS)
        data = {'name': 'alice', 'port1': ALICE_PORT1, 'submit': 'Save',
                'video_enabled': 'y'}
        for i, p in enumerate(ports, start=1):
            data['video_port_%d' % i] = str(p) if p else ''
        client.post('/admin/%d' % ALICE_PORT2, data=data)
        client.get('/logout')

    def test_owner_sees_no_options_for_unallocated_slot(self, client,
                                                        keydb_path):
        """Per-slot options for a port an owner can't allocate are noise."""
        self._allocate(client, keydb_path, [VPORT_A, 0, 0])
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/').get_data(as_text=True)
        assert 'name="video_record_1"' in html      # slot 1 allocated
        assert 'name="video_record_2"' not in html  # slot 2 is not
        assert 'not allocated' in html

    def test_admin_always_sees_all_slots(self, client, keydb_path):
        """An admin may allocate a port in the same save, so keep them."""
        self._allocate(client, keydb_path, [VPORT_A, 0, 0])
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        for i in (1, 2, 3):
            assert 'name="video_record_%d"' % i in html
            assert 'name="video_port_%d"' % i in html


class TestVideoOptionsCollapse:
    """The settings block is hidden until video is enabled.

    It is long -- three ports with per-slot options, two passwords, a
    grace window and a disk budget -- and none of it means anything for
    an entry that does not use video.
    """

    def test_all_settings_live_in_the_collapsible_panel(self, client,
                                                        keydb_path):
        import re
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        panel = html.index('id="video-options"')

        def pos(name):
            m = re.search(r'name="%s"' % re.escape(name), html)
            return m.start() if m else None

        names = {n for n in re.findall(r'name="(video_[a-z0-9_]+)"', html)}
        outside = sorted(n for n in names if pos(n) < panel)
        assert outside == ['video_enabled'], \
            'these would stay visible on a disabled entry: %r' % outside
        assert len(names) > 15, 'expected the whole settings block'

    def test_toggle_script_is_loaded(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/').get_data(as_text=True)
        assert 'video-toggle.js' in html
        r = client.get('/static/video-toggle.js')
        assert r.status_code == 200

    def test_panel_ships_visible(self, client, keydb_path):
        """Progressive enhancement: the script hides it, the markup does
        not. A script failure must not strand an operator with settings
        they cannot reach."""
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/').get_data(as_text=True)
        m = re.search(r'<div id="video-options"([^>]*)>', html)
        assert m, 'panel missing'
        assert 'hidden' not in m.group(1), \
            'panel is hidden in the markup; JS should do the hiding'

    def test_panel_is_present_for_owners_too(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/').get_data(as_text=True)
        assert 'id="video-options"' in html


class TestVideoPortCountSelector:
    """The page shows as many port slots as the entry uses, not three."""

    def test_selector_is_present_for_admins(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        assert 'name="video_port_count"' in html
        assert 'data-slot="1"' in html and 'data-slot="3"' in html

    def test_owner_has_no_selector(self, client, keydb_path):
        """Ports are an admin allocation; an owner cannot ask for more."""
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/').get_data(as_text=True)
        assert 'name="video_port_count"' not in html

    def test_unused_slots_ship_hidden(self, client, keydb_path):
        """No-JS and first paint: an entry with one port must not show
        every slot's row before the script runs."""
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        rows = re.findall(r'<div class="field video-slot" data-slot="(\d)"'
                          r'\s*([^>]*)>', html)
        assert len(rows) == keydb_lib.MAX_VIDEO_PORTS
        # Slot 1 shown, every other slot hidden.
        expected = {n: (n != 1)
                    for n in range(1, keydb_lib.MAX_VIDEO_PORTS + 1)}
        assert {int(s): ('hidden' in a) for s, a in rows} == expected

    def test_ports_default_to_the_base(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        m = re.search(r'id="video_port_1"[^>]*value="(\d+)"', html)
        assert m, 'port 1 was not prefilled'
        assert int(m.group(1)) == keydb_lib.VIDEO_PORT_BASE

    def test_later_slots_are_prefilled_too(self, client, keydb_path):
        """Raising the count must reveal a filled field, not a blank one."""
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        got = [int(re.search(r'id="video_port_%d"[^>]*value="(\d+)"'
                             % i, html).group(1)) for i in (1, 2, 3)]
        assert got == [keydb_lib.VIDEO_PORT_BASE,
                       keydb_lib.VIDEO_PORT_BASE + 1,
                       keydb_lib.VIDEO_PORT_BASE + 2]

    def test_saving_a_disabled_entry_allocates_nothing(self, client,
                                                       keydb_path):
        """Every slot is prefilled with a suggestion. Saving an entry
        that has video off must not turn those into a real allocation."""
        resp = _admin_post(client_logged_in_as_admin(client), ALICE_PORT2,
                           video_port_count='3', video_port_1='40001',
                           video_port_2='40002', video_port_3='40003')
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_ports == [0, 0, 0, 0, 0]
        assert not ke.video_enabled()

    def test_count_bounds_what_is_stored(self, client, keydb_path):
        """Slots past the count are dropped even though their hidden
        fields still submit."""
        resp = _admin_post(client_logged_in_as_admin(client), ALICE_PORT2,
                           video_enabled='y', video_port_count='1',
                           video_port_1=str(VPORT_A),
                           video_port_2=str(VPORT_B))
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_ports == [VPORT_A, 0, 0, 0, 0]
        assert ke.video_port_count() == 1

    def test_count_two_stores_two(self, client, keydb_path):
        resp = _admin_post(client_logged_in_as_admin(client), ALICE_PORT2,
                           video_enabled='y', video_port_count='2',
                           video_port_1=str(VPORT_A),
                           video_port_2=str(VPORT_B))
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_ports == [VPORT_A, VPORT_B, 0, 0, 0]
        assert ke.video_port_count() == 2

    def test_a_submission_without_the_count_keeps_every_slot(self, client,
                                                             keydb_path):
        """The field is new. A caller that predates it must not have
        slots 2 and 3 silently dropped onto the field default of 1."""
        resp = _admin_post(client_logged_in_as_admin(client), ALICE_PORT2,
                           video_enabled='y', video_port_1=str(VPORT_A),
                           video_port_2=str(VPORT_B))
        assert resp.status_code == 302
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.video_ports == [VPORT_A, VPORT_B, 0, 0, 0]

    def test_allocated_ports_are_not_renumbered_on_reopen(self, client,
                                                          keydb_path):
        """Opening the edit page of a streaming entry must offer back the
        port it is already on, not the next free one."""
        _admin_post(client_logged_in_as_admin(client), ALICE_PORT2,
                    video_enabled='y', video_port_count='1',
                    video_port_1=str(VPORT_A))
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        m = re.search(r'id="video_port_1"[^>]*value="(\d+)"', html)
        assert int(m.group(1)) == VPORT_A

    def test_count_reflects_what_is_allocated_on_reopen(self, client,
                                                        keydb_path):
        _admin_post(client_logged_in_as_admin(client), ALICE_PORT2,
                    video_enabled='y', video_port_count='2',
                    video_port_1=str(VPORT_A), video_port_2=str(VPORT_B))
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        rows = re.findall(r'<div class="field video-slot" data-slot="(\d)"'
                          r'\s*([^>]*)>', html)
        # Two allocated: slots 1 and 2 shown, the rest hidden.
        expected = {n: (n > 2)
                    for n in range(1, keydb_lib.MAX_VIDEO_PORTS + 1)}
        assert {int(s): ('hidden' in a) for s, a in rows} == expected


def client_logged_in_as_admin(client):
    login_as(client, BOB_PORT1, BOB_PASS)
    return client


class TestRtmpPathField:
    """RTMP publishing does nothing until the slot knows the camera's
    app/stream, so it has to be settable here and not only from the CLI."""

    def test_field_is_present_per_slot(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        for n in (1, 2, 3):
            assert 'name="video_rtmp_%d"' % n in html

    def test_owner_can_set_it(self, client, keydb_path):
        """It describes what the camera sends, not an allocation, so an
        owner may change it like the other per-slot options."""
        _owner_post(client_as_owner(client), video_enabled='y',
                    video_rtmp_1='PhoenixFPV/FPV')
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.rtmp_path(0) == 'PhoenixFPV/FPV'

    def test_round_trips_to_the_page(self, client, keydb_path):
        """An owner only sees per-slot controls for an allocated slot,
        so allocate one first -- otherwise this asserts nothing."""
        login_as(client, BOB_PORT1, BOB_PASS)
        _admin_post(client, ALICE_PORT2, video_enabled='y',
                    video_port_1=str(VPORT_A), video_rtmp_1='PhoenixFPV/FPV')
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        assert 'PhoenixFPV/FPV' in html
        login_as(client, ALICE_PORT1, ALICE_PASS)
        assert 'PhoenixFPV/FPV' in client.get('/me/').get_data(as_text=True)

    def test_leading_and_trailing_slashes_are_normalised(self, client,
                                                        keydb_path):
        """The value is handed to the backend as a URL path, so it must
        be stored the way the URL builder expects."""
        _owner_post(client_as_owner(client), video_enabled='y',
                    video_rtmp_1='/live/cam/')
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.rtmp_path(0) == 'live/cam'

    def test_a_bad_path_is_refused_not_stored(self, client, keydb_path):
        """A space would change the URL's meaning; say so rather than
        building a different one."""
        _owner_post(client_as_owner(client), video_enabled='y',
                    video_rtmp_1='has space')
        ke = fetch_entry(keydb_path, ALICE_PORT2)
        assert ke.rtmp_path(0) == ''

    def test_blank_clears_it(self, client, keydb_path):
        _owner_post(client_as_owner(client), video_enabled='y',
                    video_rtmp_1='PhoenixFPV/FPV')
        assert fetch_entry(keydb_path, ALICE_PORT2).rtmp_path(0)
        _owner_post(client_as_owner(client), video_enabled='y',
                    video_rtmp_1='')
        assert fetch_entry(keydb_path, ALICE_PORT2).rtmp_path(0) == ''


def client_as_owner(client):
    login_as(client, ALICE_PORT1, ALICE_PASS)
    return client
