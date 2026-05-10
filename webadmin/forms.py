"""Flask-WTF forms. CSRF tokens are added automatically by FlaskForm."""
from flask_wtf import FlaskForm
from wtforms import (BooleanField, FloatField, IntegerField, PasswordField,
                     StringField, SubmitField)
from wtforms.validators import (DataRequired, Length, NumberRange, Optional,
                                EqualTo)


# Owner cap on tlog retention. Anything higher requires admin.
OWNER_MAX_TLOG_RETENTION_DAYS = 30.0
ADMIN_MAX_TLOG_RETENTION_DAYS = 36500.0  # ~100 years; effectively unbounded


class LoginForm(FlaskForm):
    port = IntegerField('Port (port1 or port2)',
                        validators=[DataRequired(),
                                    NumberRange(min=1, max=65535)])
    passphrase = PasswordField('Passphrase',
                               validators=[DataRequired(),
                                           Length(min=1, max=256)])
    submit = SubmitField('Log in')


class OwnerEditForm(FlaskForm):
    """Self-service form: name + optional new passphrase + flag toggles."""
    name = StringField('Display name', validators=[Optional(), Length(max=31)])
    new_passphrase = PasswordField(
        'New passphrase (leave blank to keep current)',
        validators=[Optional(), Length(min=4, max=256)])
    confirm_passphrase = PasswordField(
        'Confirm new passphrase',
        validators=[Optional(), EqualTo('new_passphrase',
                                        message='Passphrases do not match.')])
    bidi_sign = BooleanField(
        'Require MAVLink signing on the user side too (bi-directional signing)')
    tlog_enabled = BooleanField('Record telemetry logs (.tlog) for this entry')
    tlog_retention_days = FloatField(
        'Tlog retention (days, 0 = keep forever, owners capped at 30)',
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
        validators=[Optional(), Length(min=4, max=256)])
    confirm_passphrase = PasswordField(
        'Confirm new passphrase',
        validators=[Optional(), EqualTo('new_passphrase',
                                        message='Passphrases do not match.')])
    is_admin = BooleanField('Grant admin privilege (KEY_FLAG_ADMIN)')
    bidi_sign = BooleanField(
        'Require MAVLink signing on the user side too (bi-directional signing)')
    tlog_enabled = BooleanField('Record telemetry logs (.tlog) for this entry')
    tlog_retention_days = FloatField(
        'Tlog retention (days, 0 = keep forever)',
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
                                           Length(min=4, max=256)])
    submit = SubmitField('Add')


class DeleteForm(FlaskForm):
    """Empty form just to carry a CSRF token for the delete button."""
    submit = SubmitField('Delete')
