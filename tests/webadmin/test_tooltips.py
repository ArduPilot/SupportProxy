"""Per-field help tooltips.

Every option that is not self-explanatory carries its explanation in the
WTForms `description`, which templates/_macros.html renders as a tooltip
beside the label. Two things are worth guarding: that the tooltips
actually reach the page, and that a newly added option cannot quietly
ship without one.
"""
import re

from _test_helpers import (ALICE_PASS, ALICE_PORT1, ALICE_PORT2, BOB_PASS,
                           BOB_PORT1, login_as)

from webadmin import forms

# Fields that legitimately have no `description`.
#
# The per-slot video booleans are documented by hand in
# _video_fields.html instead: five slots x four options would mean twenty
# near-identical strings in forms.py, and the row is rendered by hand
# there anyway.
# 'passphrase' is the login password field. A tooltip on it froze
# Chrome's renderer on paste -- the tab stopped accepting input at all --
# so it deliberately carries no description and its text moved into the
# blurb above the form.
_NO_DESCRIPTION_NEEDED = {'submit', 'csrf_token', 'passphrase'}


def _documented(form_cls):
    """(fields needing a description, fields having one)."""
    form = form_cls(meta={'csrf': False})
    need, have = set(), set()
    for field in form:
        name = field.name
        if name in _NO_DESCRIPTION_NEEDED:
            continue
        if re.match(r'^video_(srt|record|rawtcp|sessok)_\d$', name):
            continue
        need.add(name)
        if field.description:
            have.add(name)
    return need, have


class TestEveryOptionIsDocumented:
    """A new option must not ship without help text."""

    def test_admin_edit_form(self, app):
        with app.test_request_context():
            need, have = _documented(forms.AdminEditForm)
        assert need - have == set(), 'fields with no description'

    def test_owner_edit_form(self, app):
        with app.test_request_context():
            need, have = _documented(forms.OwnerEditForm)
        assert need - have == set(), 'fields with no description'

    def test_admin_add_form(self, app):
        with app.test_request_context():
            need, have = _documented(forms.AdminAddForm)
        assert need - have == set(), 'fields with no description'

    def test_login_form(self, app):
        with app.test_request_context():
            need, have = _documented(forms.LoginForm)
        assert need - have == set(), 'fields with no description'

    def test_the_check_would_catch_a_missing_one(self, app):
        """Guard the guard: a field with no description must be caught,
        or these tests pass for the wrong reason."""
        class Undocumented(forms.LoginForm):
            pass
        Undocumented.mystery = forms.BooleanField('Mystery option')
        with app.test_request_context():
            need, have = _documented(Undocumented)
        assert 'mystery' in need - have


class TestTooltipsRender:
    def test_admin_edit_page_has_tooltips(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        assert html.count('class="tip"') > 10

    def test_owner_page_has_tooltips(self, client, keydb_path):
        login_as(client, ALICE_PORT1, ALICE_PASS)
        html = client.get('/me/').get_data(as_text=True)
        assert html.count('class="tip"') > 8

    def test_login_page_has_tooltips(self, client):
        html = client.get('/login').get_data(as_text=True)
        assert 'class="tip"' in html

    def test_add_entry_form_has_tooltips(self, client, keydb_path):
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/').get_data(as_text=True)
        assert 'class="tip"' in html

    def test_specific_help_text_reaches_the_page(self, client, keydb_path):
        """Spot-check that the detail that used to be in the label is
        still shown, just moved into the tooltip."""
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        assert 'LOG_BACKEND_TYPE' in html          # binlog
        assert 'keeps them forever' in html        # retention
        assert 'replays' in html                   # reset timestamp

    def test_the_whole_row_is_the_target_not_a_marker(self, client,
                                                       keydb_path):
        """Aiming at a one-em "?" to read a sentence is more work than
        the sentence is worth."""
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        assert 'class="help"' not in html, 'the ? marker is gone'
        assert '>?<' not in html

    def test_reachable_without_a_pointer(self, client, keydb_path):
        """Focusing the input is what shows it for keyboard users, and
        aria-describedby ties the text to the control."""
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        assert 'aria-describedby=' in html
        assert ':focus-within' in _css_rules(client)

    def test_video_slot_options_are_documented_in_the_template(
            self, client, keydb_path):
        """These are exempt from the forms.py check, so make sure they
        really are documented where they are rendered."""
        login_as(client, BOB_PORT1, BOB_PASS)
        html = client.get('/admin/%d' % ALICE_PORT2).get_data(as_text=True)
        assert 'cannot share a port' in html       # SRT
        assert 'timestamped .ts segments' in html  # record
        assert 'ffplay tcp://' in html             # raw TCP viewers
        assert 'nowhere to put a credential' in html   # MAVLink publish

    def test_description_is_escaped(self, app):
        """Descriptions are trusted text today, but they are rendered
        into HTML, so the macro must not become an injection point if one
        ever contains a bracket."""
        from markupsafe import Markup
        from flask import render_template_string

        class F(forms.LoginForm):
            pass
        F.evil = forms.StringField('Evil',
                                   description='<script>alert(1)</script>')
        with app.test_request_context():
            f = F(meta={'csrf': False})
            out = render_template_string(
                '{% from "_macros.html" import row %}{{ row(form.evil) }}',
                form=f)
        assert '<script>' not in out
        assert '&lt;script&gt;' in out
        assert isinstance(Markup(out), Markup)


def _css_rules(client):
    """The stylesheet with comments stripped.

    The comments quote the selectors they explain, so a test looking for
    a rule will happily match the prose about it instead."""
    css = client.get('/static/style.css').get_data(as_text=True)
    return re.sub(r'/\*.*?\*/', '', css, flags=re.S)


class TestStylesheet:
    def test_tip_rules_are_present(self, client):
        css = _css_rules(client)
        assert '.field:hover > .tip' in css
        assert ':focus' in css, 'tooltip must open on keyboard focus'

    def test_row_selector_is_direct_child_only(self, client):
        """The per-slot video row holds several separately documented
        checkboxes; a descendant selector would throw all of their
        tooltips up at once when the row is hovered."""
        css = _css_rules(client)
        assert '.field:hover > .tip' in css
        assert '.field:hover .tip' not in css.replace('.field:hover > .tip', '')

    def test_appearing_is_delayed(self, client):
        """Without a delay, every row crossed on the way to the wanted
        one flashes a tooltip."""
        css = _css_rules(client)
        m = re.search(r'\.field:hover > \.tip[^{]*\{([^}]*)\}', css)
        assert m, 'no .field:hover > .tip rule'
        assert 'transition' in m.group(1)
        assert '0.4s' in m.group(1), 'no delay before the tooltip appears'

    def test_tooltip_never_swallows_a_click(self, client):
        css = _css_rules(client)
        assert 'pointer-events: none' in css

    def test_tip_is_anchored_to_the_field_not_the_marker(self, client):
        """Anchoring to the marker puts the tip's left edge wherever the
        label ends, so a marker in the right-hand part of a row pushes
        its tip off the page on a narrow screen -- and CSS cannot measure
        the space to flip it. Anchored to .field it is always within the
        body's own width."""
        css = _css_rules(client)
        assert re.search(r'\.field\s*\{[^}]*position:\s*relative', css), \
            '.field must be the containing block'
        assert not re.search(r'\.help\s*\{[^}]*position:\s*relative', css), \
            '.help must stay unpositioned or it becomes the anchor again'

    def test_tip_width_is_capped_by_the_viewport(self, client):
        """Body is max-width 960px with 1rem padding, so below that the
        content width is exactly 100vw - 2rem. Capping the tip to the
        same value is what keeps it on screen on a phone."""
        css = client.get('/static/style.css').get_data(as_text=True)
        assert '100vw' in css, 'tip width must be bounded by the viewport'
