from urlparse import urlparse
from flask import request, url_for, redirect
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField, HiddenField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


def is_safe_redirect_url(target):
    """Assists in preventing open redirect attacks by checking URLs.

    Target URL is accepted as safe if its scheme (protocol) and
    netloc (hostname) fields match those of the current application.
    Target URL is also accepted as safe if its scheme and netloc fields
    are empty, since it's a relative link in the current application.
    Additionaly, the path field is checked for extra slashes which would
    signify a malformed URL. The motivation behind the check for extra
    slashes is because when the redirect URL is a phony relative URL such as
    "////google.com", a redirect is issued and in turn the browser issues
    a GET request for "//google.com", which causes the development server
    to issue a 301 redirect to "google.com". I've found that Nginx does not
    exhibit this behavior, but I figured the extra check couldn't hurt.

    Args:
        target: The redirect URL.

    Returns:
        True if the URL is determined to be safe.
    """
    host_url = urlparse(request.host_url)
    target_url = urlparse(target)
    if (target_url.scheme == host_url.scheme and
            target_url.netloc == host_url.netloc):
        return True
    if (not target_url.scheme and not target_url.netloc and
            '//' not in target_url.path):
        return True
    return False


class RedirectForm(Form):
    next = HiddenField()

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        if request.method == 'GET' and request.referrer != request.url:
            self.next.data = request.referrer

    def redirect(self, endpoint='index', **values):
        for target in request.args.get('next'), self.next.data:
            if target and is_safe_redirect_url(target):
                return redirect(target)
        return redirect(url_for(endpoint, **values))


class LoginForm(RedirectForm):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class ReauthenticationForm(RedirectForm):
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Submit')


class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                           Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Length(8, 64),
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class ChangeUsernameForm(Form):
    username = StringField('New Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Update Username')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class ChangePasswordForm(RedirectForm):
    current_password = PasswordField('Current Password', validators=[Required()])
    password = PasswordField('New Password', validators=[Length(8, 64),
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm New Password', validators=[Required()])
    submit = SubmitField('Update Password')


class PasswordResetRequestForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField('Reset Password')


class PasswordResetForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('New Password', validators=[Length(8, 64),
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm Password', validators=[Required()])
    submit = SubmitField('Reset Password')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first() is None:
            raise ValidationError('Unknown email address.')


class ChangeEmailForm(RedirectForm):
    email = StringField('New Email', validators=[Required(), Length(1, 64),
                                                 Email()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Update Email Address')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
