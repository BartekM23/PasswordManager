from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Email, ValidationError, EqualTo
import string


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(min=4, max=40), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=40)])
    confirm_password = PasswordField('Repeat Password',
                                     validators=[DataRequired(), Length(min=6, max=40), EqualTo('password')])
    username = StringField("Name", validators=[DataRequired(), Length(min=2, max=40)])
    submit = SubmitField("Sign Me Up!")

    def validate_password(self, password):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.password.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")

    def validate_email(self, email):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.email.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")

    def validate_confirm_password(self, confirm_password):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.confirm_password.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")

    def validate_username(self, username):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.username.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(min=4, max=40)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=40)])
    submit = SubmitField("Let Me In!")

    def validate_email(self, email):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.email.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")

    def validate_password(self, password):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.password.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")


class ChangePassword(FlaskForm):
    old_password = PasswordField("Old password", validators=[DataRequired(), Length(min=6, max=40)])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=6, max=40)])
    repeated_new_password = PasswordField("Repeat new password", validators=[DataRequired(), Length(min=6, max=40),
                                                                             EqualTo('new_password')])
    submit = SubmitField("Change password!")

    def validate_old_password(self, old_password):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.old_password.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")

    def validate_new_password(self, new_password):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.new_password.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")

    def validate_repeated_new_password(self, repeated_new_password):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.repeated_new_password.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")


class FormAddPassword(FlaskForm):
    domain_name = StringField("Domain name", validators=[DataRequired(), Length(min=1, max=50)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=40)])
    confirm_password = PasswordField('Repeat Password',
                                   validators=[DataRequired(), Length(min=6, max=40), EqualTo('password')])
    submit = SubmitField("Add!")

    def validate_domain_name(self, domain_name):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.domain_name.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")

    def validate_password(self, password):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.password.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")

    def validate_confirm_password(self, confirm_password):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.confirm_password.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")

#For reset password also
class FormSharePassword(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(min=4, max=40), Email()])
    submit = SubmitField("Add!")

    def validate_email(self, email):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.email.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")


class FormResetPassword(FlaskForm):
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=6, max=40)])
    repeated_new_password = PasswordField("Repeat new password", validators=[DataRequired(), Length(min=6, max=40),
                                                                             EqualTo('new_password')])
    submit = SubmitField("Change password!")

    def validate_new_password(self, new_password):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.new_password.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")

    def validate_repeated_new_password(self, repeated_new_password):
        allowed_chars = string.digits + string.ascii_letters + '.@'
        for char in self.repeated_new_password.data:
            if char not in allowed_chars:
                raise ValidationError(
                    f"Character {char} is not allowed")
