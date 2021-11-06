import re

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email, Length, EqualTo, ValidationError


def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(
                f"Character {char} is not allowed.")


class RegisterForm(FlaskForm):
    email = StringField(validators=[Required(), Email()])
    firstname = StringField(validators=[Required(), character_check])
    lastname = StringField(validators=[Required(), character_check])
    phone = StringField(validators=[Required()])
    password = PasswordField(validators=[Required(), Length(min=6, max=12,
                                                            message='Password must be between 6 and 12 characters in length.')])
    confirm_password = PasswordField(
        validators=[Required(), EqualTo('password', message='Both password fields must be equal!')])
    pin_key = StringField(validators=[Required(), character_check,
                                      Length(min=32, max=32, message='PIN key must be exactly 32 characters')])
    submit = SubmitField()

    def validate_password(self, password):
        p = re.compile(r'(?=.*\d)(?=.*[A-Z])(?=.*\W)(?=.*[a-z])')
        if not p.match(self.password.data):
            raise ValidationError(
                "Password must contain at least 1 digit, 1 lowercase, 1 uppercase and 1 special character.")

    def validate_phone(self, phone):
        p = re.compile(r'\d{4}-\d{3}-\d{4}')
        if not p.match(self.phone.data):
            raise ValidationError("Phone must be in format XXXX-XXX-XXXX")


class LoginForm(FlaskForm):
    username = StringField(validators=[Required(), Email()])
    password = PasswordField(validators=[Required()])
    pin = StringField(validators=[Required()])
    submit = SubmitField()
