from urlparse import urlparse, urlunparse
from flask import render_template, redirect, request, url_for, flash, session
from flask.ext.login import login_user, logout_user, login_required, \
    current_user
from . import auth
from .. import db, login_manager
from ..models import User
from ..email import send_email
from ..flash_category import FlashCategory
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, \
    PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm, \
    ChangeUsernameForm


login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = FlashCategory.INFO
login_manager.needs_refresh_message = (
    'To protect your account, please reauthenticate to access this page.'
)
login_manager.needs_refresh_message_category = FlashCategory.WARNING


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.verify_auth_token(session.get('auth_token')):
            logout_user()
            flash('Your session has expired.', FlashCategory.DANGER)
            return redirect(url_for('auth.login'))
        if (not current_user.confirmed and
                request.endpoint[:5] != 'auth.' and
                request.endpoint != 'static'):
            return redirect(url_for('auth.unconfirmed'))


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
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            session['auth_token'] = user.auth_token
            return form.redirect('main.index')
        flash('Invalid username or password.', FlashCategory.DANGER)
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have logged out.', FlashCategory.SUCCESS)
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash('Check your inbox! A confirmation email has been sent.',
              FlashCategory.INFO)
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('Your account is confirmed. Thank you!',
              FlashCategory.SUCCESS)
    else:
        flash('The confirmation link is invalid or has expired.',
              FlashCategory.DANGER)
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent.', FlashCategory.INFO)
    return redirect(url_for('main.index'))


@auth.route('/change-username', methods=['GET', 'POST'])
@login_required
def change_username():
    form = ChangeUsernameForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            current_user.change_username(form.username.data)
            session['auth_token'] = current_user.auth_token
            flash('Your username has been updated.', FlashCategory.SUCCESS)
            return redirect(url_for('main.user',
                                    username=current_user.username))
        else:
            flash('Invalid password.', FlashCategory.DANGER)
    return render_template("auth/change_username.html", form=form)


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            session['auth_token'] = current_user.auth_token
            flash('Your password has been updated.', FlashCategory.SUCCESS)
            return redirect(url_for('main.user',
                                    username=current_user.username))
        else:
            flash('Invalid password.', FlashCategory.DANGER)
    return render_template("auth/change_password.html", form=form)


@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password',
                       'auth/email/reset_password',
                       user=user, token=token,
                       next=request.args.get('next'))
        flash('An email with instructions for resetting your password has been '
              'sent.', FlashCategory.INFO)
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
            flash('Your password has been updated.', FlashCategory.SUCCESS)
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_email_change_token(new_email)
            send_email(new_email, 'Confirm Your Email Address',
                       'auth/email/change_email',
                       user=current_user, token=token)
            flash('An email with instructions for confirming your new email '
                  'address has been sent.', FlashCategory.INFO)
            return redirect(url_for('main.user',
                                    username=current_user.username))
        else:
            flash('Invalid password.', FlashCategory.DANGER)
    return render_template("auth/change_email.html", form=form)


@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        session['auth_token'] = current_user.auth_token
        flash('Your email address has been updated.',
              FlashCategory.SUCCESS)
    else:
        flash('Invalid request.', FlashCategory.DANGER)
    return redirect(url_for('main.user',
                            username=current_user.username))
