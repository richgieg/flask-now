from urlparse import urlparse, urlunparse
from flask import render_template, redirect, request, url_for, session, \
    make_response
from flask.ext.login import login_user, logout_user, login_required, \
    current_user, fresh_login_required, confirm_login, login_fresh
from . import auth
from .. import db, login_manager
from ..decorators import fresh_admin_or_404
from ..models import User, LogEvent
from ..email import send_email
from ..messages import AuthMessages, flash_it
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, \
    PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm, \
    ChangeUsernameForm, ReauthenticationForm


# Set Flask-Login flash messages.
login_manager.login_message = AuthMessages.LOGIN_REQUIRED[0]
login_manager.login_message_category = AuthMessages.LOGIN_REQUIRED[1]
login_manager.needs_refresh_message = AuthMessages.REFRESH_REQUIRED[0]
login_manager.needs_refresh_message_category = AuthMessages.REFRESH_REQUIRED[1]


def verify_password(user, password):
    is_valid_password = user.verify_password(password)
    if user.locked:
        session['_locked'] = True
    if not user.enabled:
        session['_disabled'] = True
    return is_valid_password


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.verify_auth_token(session.get('auth_token')):
            LogEvent.session_bad_auth_token(current_user)
            logout_user()
            flash_it(AuthMessages.SESSION_EXPIRED)
            return redirect(url_for('auth.login'))
        if (not current_user.confirmed and
                request.endpoint[:5] != 'auth.' and
                request.endpoint != 'static'):
            return redirect(url_for('auth.unconfirmed'))


@auth.after_app_request
def after_request(response):
    if session.get('_disabled', None):
        logout_user()
        return make_response(redirect(url_for('auth.disabled')))
    if session.get('_locked', None):
        logout_user()
        return make_response(redirect(url_for('auth.locked')))
    return response


@auth.route('/locked')
def locked():
    if session.pop('_locked', None):
        return render_template('auth/locked.html')
    return redirect(url_for('auth.login'))


@auth.route('/disabled')
def disabled():
    if session.pop('_disabled', None):
        session.pop('_locked', None)
        return render_template('auth/disabled.html')
    return redirect(url_for('auth.login'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and verify_password(user, form.password.data):
            login_user(user, form.remember_me.data)
            session['auth_token'] = user.auth_token
            LogEvent.log_in(user)
            return form.redirect('main.index')
        elif user is None:
            LogEvent.incorrect_email()
        flash_it(AuthMessages.INVALID_CREDENTIALS)
    return render_template('auth/login.html', form=form)


@auth.route('/reauthenticate', methods=['GET', 'POST'])
def reauthenticate():
    # This isn't wrapped with login_required because it wouldn't make sense
    # to require a login to access the reauthenticate page. Instead, the
    # following if statement takes its place.
    if not current_user.is_authenticated or login_fresh():
        return redirect(url_for('main.index'))
    form = ReauthenticationForm()
    if form.validate_on_submit():
        if verify_password(current_user, form.password.data):
            confirm_login()
            LogEvent.reauthenticate(current_user)
            return form.redirect('main.index')
        flash_it(AuthMessages.INVALID_PASSWORD)
    return render_template('auth/reauthenticate.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    LogEvent.log_out(current_user)
    logout_user()
    flash_it(AuthMessages.LOG_OUT)
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    # TODO: Fix possible synchronization issue. If the current number of users
    # is one less than APP_MAX_USERS, and two users happen to post back the
    # completed registration form at the exact same time and both move beyond
    # this check, is it possible that the number of users could be one greater
    # than APP_MAX_USERS?
    if not User.can_register():
        LogEvent.register_account_blocked()
        return render_template('auth/register_disabled.html')
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        LogEvent.register_account(user)
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash_it(AuthMessages.CONFIRM_ACCOUNT)
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash_it(AuthMessages.ACCOUNT_CONFIRMED)
    else:
        flash_it(AuthMessages.INVALID_CONFIRMATION_LINK)
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash_it(AuthMessages.CONFIRM_ACCOUNT)
    return redirect(url_for('main.index'))


@auth.route('/change-username', methods=['GET', 'POST'])
@fresh_login_required
def change_username():
    form = ChangeUsernameForm()
    if form.validate_on_submit():
        if verify_password(current_user, form.password.data):
            current_user.change_username(form.username.data)
            session['auth_token'] = current_user.auth_token
            flash_it(AuthMessages.USERNAME_UPDATED)
            return redirect(url_for('main.user',
                                    username=current_user.username))
        else:
            flash_it(AuthMessages.INVALID_PASSWORD)
    return render_template("auth/change_username.html", form=form)


@auth.route('/change-password', methods=['GET', 'POST'])
@fresh_login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if verify_password(current_user, form.current_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            session['auth_token'] = current_user.auth_token
            flash_it(AuthMessages.PASSWORD_UPDATED)
            return form.redirect(url_for('main.user',
                                         username=current_user.username))
        else:
            flash_it(AuthMessages.INVALID_PASSWORD)
    return render_template("auth/change_password.html", form=form)


@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if not user.enabled:
                flash_it(AuthMessages.PASSWORD_RESET_REQUEST_DISABLED_ACCOUNT)
                LogEvent.password_reset_request_disabled_account(user)
            else:
                token = user.generate_reset_token()
                send_email(user.email, 'Reset Your Password',
                           'auth/email/reset_password',
                           user=user, token=token,
                           next=request.args.get('next'))
                flash_it(AuthMessages.PASSWORD_RESET_REQUEST)
        else:
            # This is just to trick anyone guessing email addresses.
            flash_it(AuthMessages.PASSWORD_RESET_REQUEST)
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash_it(AuthMessages.PASSWORD_UPDATED)
            if user.locked:
                user.locked = False
                flash_it(AuthMessages.ACCOUNT_UNLOCKED)
            return redirect(url_for('auth.login'))
        else:
            flash_it(AuthMessages.INVALID_PASSWORD_RESET_LINK)
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change-email', methods=['GET', 'POST'])
@fresh_login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if verify_password(current_user, form.password.data):
            new_email = form.email.data
            token = current_user.generate_email_change_token(new_email)
            send_email(new_email, 'Confirm Your Email Address',
                       'auth/email/change_email',
                       user=current_user, token=token)
            flash_it(AuthMessages.EMAIL_CHANGE_REQUEST)
            return form.redirect(url_for('main.user',
                                         username=current_user.username))
        else:
            flash_it(AuthMessages.INVALID_PASSWORD)
    return render_template("auth/change_email.html", form=form)


@auth.route('/change-email/<token>')
@fresh_login_required
def change_email(token):
    if current_user.change_email(token):
        session['auth_token'] = current_user.auth_token
        flash_it(AuthMessages.EMAIL_UPDATED)
    else:
        flash_it(AuthMessages.INVALID_CONFIRMATION_LINK)
    return redirect(url_for('main.user',
                            username=current_user.username))


@auth.route('/event-log')
@fresh_admin_or_404
def event_log():
    try:
        records = int(request.args.get('records'))
    except (TypeError, ValueError):
        records = 25
    events = (
        LogEvent.query
            .order_by(LogEvent.logged_at.desc())
            .limit(records)
            .all()
    )
    return render_template('auth/event_log.html', events=events)
