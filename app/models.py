from datetime import datetime, timedelta
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import Signer, TimedJSONWebSignatureSerializer as Serializer,\
    SignatureExpired, BadSignature
from flask import current_app, request, session
from flask.ext.login import UserMixin, AnonymousUserMixin, make_secure_token
from sqlalchemy.ext.hybrid import hybrid_property
from . import db, login_manager


class AccountPolicy:
    LOCKOUT_POLICY_ENABLED = True
    LOCKOUT_THRESHOLD = 5
    RESET_THRESHOLD_AFTER = timedelta(minutes=30)


class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class LogEventType(db.Model):
    __tablename__ = 'log_event_types'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    context = db.Column(db.String(64))
    events = db.relationship('LogEvent', backref='type')
    # The id values must not be changed.
    EVENT_TYPES = {
        'log_in': {'id': 1, 'context': 'info'},
        'log_out': {'id': 2, 'context': 'info'},
        'reauthenticate': {'id': 3, 'context': 'info'},
        'incorrect_password': {'id': 4, 'context': 'warning'},
        'incorrect_email': {'id': 5, 'context': 'warning'},
        'account_confirmed': {'id': 50, 'context': 'info'},
        'account_unconfirmed': {'id': 51, 'context': 'info'},
        'account_locked': {'id': 6, 'context': 'info'},
        'account_unlocked': {'id': 7, 'context': 'success'},
        'account_disabled': {'id': 8, 'context': 'info'},
        'account_enabled': {'id': 9, 'context': 'success'},
        'login_attempt_while_account_locked': {'id': 10, 'context': 'warning'},
        'register_account': {'id': 11, 'context': 'info'},
        'register_account_blocked': {'id': 12, 'context': 'info'},
        'confirm_account_request': {'id': 13, 'context': 'info'},
        'confirm_account_complete': {'id': 14, 'context': 'success'},
        'confirm_account_token_expired': {'id': 15, 'context': 'warning'},
        'confirm_account_token_invalid': {'id': 16, 'context': 'danger'},
        'confirm_account_user_id_spoof': {'id': 17, 'context': 'danger'},
        'session_bad_auth_token': {'id': 18, 'context': 'warning'},
        'remember_me_bad_auth_token': {'id': 19, 'context': 'warning'},
        'remember_me_cookie_malformed': {'id': 20, 'context': 'danger'},
        'remember_me_authenticated': {'id': 21, 'context': 'info'},
        'password_change': {'id': 22, 'context': 'info'},
        'username_change': {'id': 23, 'context': 'info'},
        'email_change_request': {'id': 24, 'context': 'info'},
        'email_change_complete': {'id': 25, 'context': 'success'},
        'email_change_token_expired': {'id': 26, 'context': 'warning'},
        'email_change_token_invalid': {'id': 27, 'context': 'danger'},
        'email_change_user_id_spoof': {'id': 28, 'context': 'danger'},
        'password_reset_request': {'id': 29, 'context': 'info'},
        'password_reset_complete': {'id': 30, 'context': 'success'},
        'password_reset_token_expired': {'id': 31, 'context': 'warning'},
        'password_reset_token_invalid': {'id': 32, 'context': 'danger'},
        'password_reset_user_id_spoof': {'id': 33, 'context': 'danger'},
        'login_attempt_while_account_disabled': {
            'id': 34,
            'context': 'warning'
        },
        'account_locked_by_failed_logins': {
            'id': 35,
            'context': 'danger'
        },
        'password_reset_request_disabled_account': {
            'id': 36,
            'context': 'warning'
        },
    }

    @staticmethod
    def insert_event_types():
        for name, data in LogEventType.EVENT_TYPES.iteritems():
            event_type = LogEventType.query.get(data['id'])
            if event_type is None:
                event_type = LogEventType(id=data['id'])
            event_type.name = name
            event_type.context = data['context']
            db.session.add(event_type)
        db.session.commit()

    def __repr__(self):
        return '<LogEventType %r>' % self.name


class LogEvent(db.Model):
    __tablename__ = 'log_events'
    id = db.Column(db.Integer, primary_key=True)
    type_id = db.Column(db.Integer, db.ForeignKey('log_event_types.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    ip_address = db.Column(db.String(48))
    logged_at = db.Column(db.DateTime(), default=datetime.utcnow)

    @staticmethod
    def _log(type_id, user=None):
        if current_app.config['APP_EVENT_LOGGING']:
            event = LogEvent(type_id=type_id, user=user,
                             ip_address=request.remote_addr)
            db.session.add(event)
            db.session.commit()

    @staticmethod
    def log_in(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['log_in']['id'],
            user
        )

    @staticmethod
    def log_out(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['log_out']['id'],
            user
        )

    @staticmethod
    def register_account(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['register_account']['id'],
            user
        )

    @staticmethod
    def confirm_account_complete(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['confirm_account_complete']['id'],
            user
        )

    @staticmethod
    def reauthenticate(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['reauthenticate']['id'],
            user
        )

    @staticmethod
    def remember_me_bad_auth_token():
        LogEvent._log(
            LogEventType.EVENT_TYPES['remember_me_bad_auth_token']['id']
        )

    @staticmethod
    def remember_me_cookie_malformed():
        LogEvent._log(
            LogEventType.EVENT_TYPES['remember_me_cookie_malformed']['id']
        )

    @staticmethod
    def remember_me_authenticated(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['remember_me_authenticated']['id'],
            user
        )

    @staticmethod
    def session_bad_auth_token(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['session_bad_auth_token']['id'],
            user
        )

    @staticmethod
    def incorrect_password(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['incorrect_password']['id'],
            user
        )

    @staticmethod
    def incorrect_email():
        LogEvent._log(LogEventType.EVENT_TYPES['incorrect_email']['id'])

    @staticmethod
    def password_change(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['password_change']['id'],
            user
        )

    @staticmethod
    def username_change(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['username_change']['id'],
            user
        )

    @staticmethod
    def email_change_request(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['email_change_request']['id'],
            user
        )

    @staticmethod
    def email_change_complete(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['email_change_complete']['id'],
            user
        )

    @staticmethod
    def password_reset_request(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['password_reset_request']['id'],
            user
        )

    @staticmethod
    def password_reset_complete(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['password_reset_complete']['id'],
            user
        )

    @staticmethod
    def account_confirmed(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['account_confirmed']['id'],
            user
        )

    @staticmethod
    def account_unconfirmed(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['account_unconfirmed']['id'],
            user
        )

    @staticmethod
    def account_locked(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['account_locked']['id'],
            user
        )

    @staticmethod
    def account_unlocked(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['account_unlocked']['id'],
            user
        )

    @staticmethod
    def account_disabled(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['account_disabled']['id'],
            user
        )

    @staticmethod
    def account_enabled(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['account_enabled']['id'],
            user
        )

    @staticmethod
    def login_attempt_while_account_locked(user):
        LogEvent._log(
            (LogEventType.EVENT_TYPES
                ['login_attempt_while_account_locked']['id']),
            user
        )

    @staticmethod
    def login_attempt_while_account_disabled(user):
        LogEvent._log(
            (LogEventType.EVENT_TYPES
                ['login_attempt_while_account_disabled']['id']),
            user
        )

    @staticmethod
    def confirm_account_token_expired(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['confirm_account_token_expired']['id'],
            user
        )

    @staticmethod
    def confirm_account_token_invalid(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['confirm_account_token_invalid']['id'],
            user
        )

    @staticmethod
    def confirm_account_user_id_spoof(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['confirm_account_user_id_spoof']['id'],
            user
        )

    @staticmethod
    def email_change_token_expired(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['email_change_token_expired']['id'],
            user
        )

    @staticmethod
    def email_change_token_invalid(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['email_change_token_invalid']['id'],
            user
        )

    @staticmethod
    def email_change_user_id_spoof(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['email_change_user_id_spoof']['id'],
            user
        )

    @staticmethod
    def password_reset_token_expired(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['password_reset_token_expired']['id'],
            user
        )

    @staticmethod
    def password_reset_token_invalid(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['password_reset_token_invalid']['id'],
            user
        )

    @staticmethod
    def password_reset_user_id_spoof(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['password_reset_user_id_spoof']['id'],
            user
        )

    @staticmethod
    def confirm_account_request(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['confirm_account_request']['id'],
            user
        )

    @staticmethod
    def register_account_blocked():
        LogEvent._log(
            LogEventType.EVENT_TYPES['register_account_blocked']['id']
        )

    @staticmethod
    def account_locked_by_failed_logins(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['account_locked_by_failed_logins']['id'],
            user
        )

    @staticmethod
    def password_reset_request_disabled_account(user):
        LogEvent._log(
            (LogEventType.EVENT_TYPES
                ['password_reset_request_disabled_account']['id']),
            user
        )

    def __repr__(self):
        return '<LogEvent %r>' % self.type.name


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    _confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    auth_token = db.Column(db.String(128), unique=True, index=True)
    last_failed_login_attempt = db.Column(db.DateTime(),
                                          default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    _locked = db.Column(db.Boolean, default=False)
    _enabled = db.Column(db.Boolean, default=True)
    log_events = db.relationship('LogEvent', backref='user')

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['APP_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        self.update_avatar_hash()
        self.update_auth_token()

    @staticmethod
    def can_register():
        if not current_app.config['APP_ALLOW_NEW_USERS']:
            return False
        else:
            if not current_app.config['APP_MAX_USERS']:
                return True
            else:
                return (
                    db.session.query(User).count() <
                        current_app.config['APP_MAX_USERS']
                )

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
        self.update_auth_token()
        LogEvent.password_change(self)

    def verify_password(self, password):
        if not AccountPolicy.LOCKOUT_POLICY_ENABLED:
            if check_password_hash(self.password_hash, password):
                return True
            else:
                LogEvent.incorrect_password(self)
                return False
        if self.locked or not self.enabled:
            if not check_password_hash(self.password_hash, password):
                LogEvent.incorrect_password(self)
            if self.locked:
                LogEvent.login_attempt_while_account_locked(self)
            if not self.enabled:
                LogEvent.login_attempt_while_account_disabled(self)
            return False
        if check_password_hash(self.password_hash, password):
            self.last_failed_login_attempt = None
            self.failed_login_attempts = 0
            return True
        LogEvent.incorrect_password(self)
        if self.last_failed_login_attempt:
            if ((datetime.utcnow() - self.last_failed_login_attempt) >
                    AccountPolicy.RESET_THRESHOLD_AFTER):
                self.failed_login_attempts = 0
        self.last_failed_login_attempt = datetime.utcnow()
        self.failed_login_attempts += 1
        if self.failed_login_attempts == AccountPolicy.LOCKOUT_THRESHOLD:
            self.locked = True
            LogEvent.account_locked_by_failed_logins(self)
        return False

    @hybrid_property
    def confirmed(self):
        return self._confirmed

    @confirmed.setter
    def confirmed(self, confirmed):
        if confirmed and not self._confirmed:
            self._confirmed = True
            LogEvent.account_confirmed(self)
        elif not confirmed and self._confirmed:
            self._confirmed = False
            LogEvent.account_unconfirmed(self)

    @property
    def locked(self):
        return self._locked

    @locked.setter
    def locked(self, locked):
        if locked and not self._locked:
            self._locked = True
            # Invalidate sessions and remember cookies.
            self.randomize_auth_token()
            LogEvent.account_locked(self)
        elif not locked and self._locked:
            self._locked = False
            self.failed_login_attempts = 0
            self.last_failed_login_attempt = None
            LogEvent.account_unlocked(self)

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        if enabled and not self._enabled:
            self._enabled = True
            LogEvent.account_enabled(self)

        elif not enabled and self._enabled:
            self._enabled = False
            # Invalidate sessions and remember cookies.
            self.randomize_auth_token()
            LogEvent.account_disabled(self)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        LogEvent.confirm_account_request(self)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            LogEvent.confirm_account_token_expired(self)
            return False
        except BadSignature:
            LogEvent.confirm_account_token_invalid(self)
            return False
        if data.get('confirm') != self.id:
            LogEvent.confirm_account_user_id_spoof(self)
            return False
        self.confirmed = True
        LogEvent.confirm_account_complete(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        LogEvent.password_reset_request(self)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            LogEvent.password_reset_token_expired(self)
            return False
        except BadSignature:
            LogEvent.password_reset_token_invalid(self)
            return False
        if data.get('reset') != self.id:
            LogEvent.password_reset_user_id_spoof(self)
            return False
        self.password = new_password
        LogEvent.password_reset_complete(self)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        LogEvent.email_change_request(self)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            LogEvent.email_change_token_expired(self)
            return False
        except BadSignature:
            LogEvent.email_change_token_invalid(self)
            return False
        if data.get('change_email') != self.id:
            LogEvent.email_change_user_id_spoof(self)
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.update_avatar_hash()
        self.update_auth_token()
        LogEvent.email_change_complete(self)
        return True

    def change_username(self, username):
        self.username = username
        self.update_auth_token()
        LogEvent.username_change(self)

    def can(self, permissions):
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def ping(self):
        self.last_seen = datetime.utcnow()

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or self.generate_avatar_hash()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def generate_avatar_hash(self):
        if self.email is not None:
            return hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return None

    def update_avatar_hash(self):
        self.avatar_hash = self.generate_avatar_hash()

    def generate_auth_token(self):
        if (self.email is not None and self.username is not None and
                self.password_hash is not None):
            return make_secure_token(self.email, self.username,
                                     self.password_hash)
        return None

    def randomize_auth_token(self):
        self.auth_token = make_secure_token(
            generate_password_hash(current_app.config['SECRET_KEY']))

    def update_auth_token(self):
        self.auth_token = self.generate_auth_token()

    def verify_auth_token(self, token):
        return token == self.auth_token

    # Returns a signed version of auth_token for Flask-Login's remember cookie.
    def get_auth_token(self):
        s = Signer(current_app.config['SECRET_KEY'])
        return s.sign(self.auth_token)

    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.token_loader
def load_user_from_signed_token(signed_token):
    s = Signer(current_app.config['SECRET_KEY'])
    auth_token = None
    try:
        auth_token = s.unsign(signed_token)
    except:
        pass
    if auth_token:
        user = User.query.filter_by(auth_token=auth_token).first()
        if user:
            session['auth_token'] = user.auth_token
            LogEvent.remember_me_authenticated(user)
            return user
        else:
            LogEvent.remember_me_bad_auth_token()
    else:
        LogEvent.remember_me_cookie_malformed()
    # This causes Flask-Login to clear the "remember me" cookie. This could
    # break if Flask-Login's internal implementation changes. A better way
    # should be implemented. Perhaps install an after_request hook.
    session['remember'] = 'clear'
    return None
