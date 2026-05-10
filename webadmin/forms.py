"""Flask-WTF forms. CSRF tokens are added automatically by FlaskForm."""
from flask_wtf import FlaskForm
from wtforms import (BooleanField, FloatField, IntegerField, PasswordField,
                     StringField, SubmitField)
from wtforms.validators import (DataRequired, Length, NumberRange, Optional,
                                EqualTo)


# Owner cap on tlog retention. Anything higher requires admin.
OWNER_MAX_TLOG_RETENTION_DAYS = 30.0
ADMIN_MAX_TLOG_RETENTION_DAYS = 36500.0  # ~100 years; effectively unbounded

# Render-kwargs for "this is a brand-new passphrase, browser, don't
# autofill the user's saved login passphrase here". Without this Chrome
# happily prefills the 'New passphrase' field with the value it has
# stored for /login on this site.
_NEW_PW_KW = {'autocomplete': 'new-password', 'spellcheck': 'false',
              'autocorrect': 'off', 'autocapitalize': 'off'}
_CURRENT_PW_KW = {'autocomplete': 'current-password', 'spellcheck': 'false',
                  'autocorrect': 'off', 'autocapitalize': 'off'}


class LoginForm(FlaskForm):
    port = IntegerField('Port (port1 or port2)',
                        validators=[DataRequired(),
                                    NumberRange(min=1, max=65535)])
    passphrase = PasswordField('Passphrase',
                               validators=[DataRequired(),
                                           Length(min=1, max=256)],
                               render_kw=_CURRENT_PW_KW)
    submit = SubmitField('Log in')


class OwnerEditForm(FlaskForm):
    """Self-service form: name + optional new passphrase + flag toggles."""
    name = StringField('Display name', validators=[Optional(), Length(max=31)])
    new_passphrase = PasswordField(
        'New passphrase (leave blank to keep current)',
        validators=[Optional(), Length(min=4, max=256)],
        render_kw=_NEW_PW_KW)
    confirm_passphrase = PasswordField(
        'Confirm new passphrase',
        validators=[Optional(), EqualTo('new_passphrase',
                                        message='Passphrases do not match.')],
        render_kw=_NEW_PW_KW)
    bidi_sign = BooleanField(
        'Require MAVLink signing on the user side too (bi-directional signing)')
    tlog_enabled = BooleanField('Record telemetry logs (.tlog) for this entry')
    binlog_enabled = BooleanField(
        'Record ArduPilot bin logs over MAVLink (.bin) — '
        'firmware must have LOG_BACKEND_TYPE mavlink bit set')
    tlog_retention_days = FloatField(
        'Tlog + bin retention (days, 0 = keep forever, owners capped at 30)',
        validators=[Optional(),
                    NumberRange(min=0.0, max=OWNER_MAX_TLOG_RETENTION_DAYS)])
    reset_timestamp = BooleanField('Reset signing timestamp (recover from clock skew)')
    submit = SubmitField('Save')


class AdminEditForm(FlaskForm):
    """Admin form: same as owner plus port1 and admin flag toggle."""
    name = StringField('Display name', validators=[Optional(), Length(max=31)])
    port1 = IntegerField('User-side port (port1)',
                         validators=[DataRequired(),
                                     NumberRange(min=1, max=65535)])
    new_passphrase = PasswordField(
        'New passphrase (leave blank to keep current)',
        validators=[Optional(), Length(min=4, max=256)],
        render_kw=_NEW_PW_KW)
    confirm_passphrase = PasswordField(
        'Confirm new passphrase',
        validators=[Optional(), EqualTo('new_passphrase',
                                        message='Passphrases do not match.')],
        render_kw=_NEW_PW_KW)
    is_admin = BooleanField('Grant admin privilege (KEY_FLAG_ADMIN)')
    bidi_sign = BooleanField(
        'Require MAVLink signing on the user side too (bi-directional signing)')
    tlog_enabled = BooleanField('Record telemetry logs (.tlog) for this entry')
    binlog_enabled = BooleanField(
        'Record ArduPilot bin logs over MAVLink (.bin) — '
        'firmware must have LOG_BACKEND_TYPE mavlink bit set')
    tlog_retention_days = FloatField(
        'Tlog + bin retention (days, 0 = keep forever)',
        validators=[Optional(),
                    NumberRange(min=0.0, max=ADMIN_MAX_TLOG_RETENTION_DAYS)])
    reset_timestamp = BooleanField('Reset signing timestamp (recover from clock skew)')
    submit = SubmitField('Save')


class AdminAddForm(FlaskForm):
    port1 = IntegerField('User-side port (port1)',
                         validators=[DataRequired(),
                                     NumberRange(min=1, max=65535)])
    port2 = IntegerField('Engineer-side port (port2)',
                         validators=[DataRequired(),
                                     NumberRange(min=1, max=65535)])
    name = StringField('Display name',
                       validators=[DataRequired(), Length(max=31)])
    passphrase = PasswordField('Passphrase',
                               validators=[DataRequired(),
                                           Length(min=4, max=256)],
                               render_kw=_NEW_PW_KW)
    submit = SubmitField('Add')


class DeleteForm(FlaskForm):
    """Empty form just to carry a CSRF token for the delete button."""
    submit = SubmitField('Delete')


class KillForm(FlaskForm):
    """Empty form just to carry a CSRF token for the kill-connection button."""
    submit = SubmitField('Kill')
