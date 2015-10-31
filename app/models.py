from datetime import datetime, timedelta
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import Signer, TimedJSONWebSignatureSerializer as Serializer,\
    SignatureExpired, BadSignature
from flask import current_app, request, session
from flask.ext.login import UserMixin, AnonymousUserMixin, make_secure_token
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
    events = db.relationship('LogEvent', backref='type')
    EVENT_TYPES = {
        'log_in': 1,                            #
        'log_out': 2,                           #
        'reauthenticate': 3,                    #
        'incorrect_password': 4,                #
        'incorrect_email': 5,                   #
        'account_locked': 6,                    #
        'account_locked_hard': 7,               #
        'account_unlocked': 8,                  #
        'account_unlocked_hard': 9,             #
        'account_locked_login_attempt': 10,     #
        'register_account': 11,                 #
        'register_account_blocked': 12,         #
        'confirm_account_request': 13,          #
        'confirm_account_complete': 14,         #
        'confirm_account_token_expired': 15,    #
        'confirm_account_token_invalid': 16,    #
        'confirm_account_user_id_spoof': 17,    #
        'session_bad_auth_token': 18,           #
        'remember_me_bad_auth_token': 19,       #
        'remember_me_cookie_malformed': 20,     #
        'remember_me_authenticated': 21,        #
        'password_change': 22,                  #
        'username_change': 23,                  #
        'email_change_request': 24,             #
        'email_change_complete': 25,            #
        'email_change_token_expired': 26,       #
        'email_change_token_invalid': 27,       #
        'email_change_user_id_spoof': 28,       #
        'password_reset_request': 29,           #
        'password_reset_complete': 30,          #
        'password_reset_token_expired': 31,     #
        'password_reset_token_invalid': 32,     #
        'password_reset_user_id_spoof': 33      #
    }

    @staticmethod
    def seed_event_types():
        LogEventType.query.delete()
        db.session.commit()
        for name, id in LogEventType.EVENT_TYPES.iteritems():
            event_type = LogEventType(id=id, name=name)
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
        LogEvent._log(LogEventType.EVENT_TYPES['log_in'], user)

    @staticmethod
    def log_out(user):
        LogEvent._log(LogEventType.EVENT_TYPES['log_out'], user)

    @staticmethod
    def register_account(user):
        LogEvent._log(LogEventType.EVENT_TYPES['register_account'], user)

    @staticmethod
    def confirm_account_complete(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['confirm_account_complete'], user
        )

    @staticmethod
    def reauthenticate(user):
        LogEvent._log(LogEventType.EVENT_TYPES['reauthenticate'], user)

    @staticmethod
    def remember_me_bad_auth_token():
        LogEvent._log(LogEventType.EVENT_TYPES['remember_me_bad_auth_token'])

    @staticmethod
    def remember_me_cookie_malformed():
        LogEvent._log(LogEventType.EVENT_TYPES['remember_me_cookie_malformed'])

    @staticmethod
    def remember_me_authenticated(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['remember_me_authenticated'], user
        )

    @staticmethod
    def session_bad_auth_token(user):
        LogEvent._log(LogEventType.EVENT_TYPES['session_bad_auth_token'], user)

    @staticmethod
    def incorrect_password(user):
        LogEvent._log(LogEventType.EVENT_TYPES['incorrect_password'], user)

    @staticmethod
    def incorrect_email():
        LogEvent._log(LogEventType.EVENT_TYPES['incorrect_email'])

    @staticmethod
    def password_change(user):
        LogEvent._log(LogEventType.EVENT_TYPES['password_change'], user)

    @staticmethod
    def username_change(user):
        LogEvent._log(LogEventType.EVENT_TYPES['username_change'], user)

    @staticmethod
    def email_change_request(user):
        LogEvent._log(LogEventType.EVENT_TYPES['email_change_request'], user)

    @staticmethod
    def email_change_complete(user):
        LogEvent._log(LogEventType.EVENT_TYPES['email_change_complete'], user)

    @staticmethod
    def password_reset_request(user):
        LogEvent._log(LogEventType.EVENT_TYPES['password_reset_request'], user)

    @staticmethod
    def password_reset_complete(user):
        LogEvent._log(LogEventType.EVENT_TYPES['password_reset_complete'], user)

    @staticmethod
    def account_locked(user):
        LogEvent._log(LogEventType.EVENT_TYPES['account_locked'], user)

    @staticmethod
    def account_unlocked(user):
        LogEvent._log(LogEventType.EVENT_TYPES['account_unlocked'], user)

    @staticmethod
    def account_locked_hard(user):
        LogEvent._log(LogEventType.EVENT_TYPES['account_locked_hard'], user)

    @staticmethod
    def account_unlocked_hard(user):
        LogEvent._log(LogEventType.EVENT_TYPES['account_unlocked_hard'], user)

    @staticmethod
    def account_locked_login_attempt(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['account_locked_login_attempt'], user
        )

    @staticmethod
    def confirm_account_token_expired(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['confirm_account_token_expired'], user
        )

    @staticmethod
    def confirm_account_token_invalid(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['confirm_account_token_invalid'], user
        )

    @staticmethod
    def confirm_account_user_id_spoof(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['confirm_account_user_id_spoof'], user
        )

    @staticmethod
    def email_change_token_expired(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['email_change_token_expired'], user
        )

    @staticmethod
    def email_change_token_invalid(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['email_change_token_invalid'], user
        )

    @staticmethod
    def email_change_user_id_spoof(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['email_change_user_id_spoof'], user
        )

    @staticmethod
    def password_reset_token_expired(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['password_reset_token_expired'], user
        )

    @staticmethod
    def password_reset_token_invalid(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['password_reset_token_invalid'], user
        )

    @staticmethod
    def password_reset_user_id_spoof(user):
        LogEvent._log(
            LogEventType.EVENT_TYPES['password_reset_user_id_spoof'], user
        )

    @staticmethod
    def confirm_account_request(user):
        LogEvent._log(LogEventType.EVENT_TYPES['confirm_account_request'], user)

    @staticmethod
    def register_account_blocked():
        LogEvent._log(LogEventType.EVENT_TYPES['register_account_blocked'])

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
    confirmed = db.Column(db.Boolean, default=False)
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
    locked_out = db.Column(db.Boolean, default=False)
    locked_out_hard = db.Column(db.Boolean, default=False)
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
        if self.locked_out:
            if not check_password_hash(self.password_hash, password):
                LogEvent.incorrect_password(self)
            LogEvent.account_locked_login_attempt(self)
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
            self.lock()
        return False

    def lock(self):
        self.locked_out = True
        # Generate a new random auth token, which will invalidate
        # any other active sessions for this user account.
        self.randomize_auth_token()
        LogEvent.account_locked(self)

    def unlock(self):
        if self.locked_out_hard:
            return False
        self.locked_out = False
        self.failed_login_attempts = 0
        self.last_failed_login_attempt = None
        LogEvent.account_unlocked(self)
        return True

    def lock_hard(self):
        self.lock()
        self.locked_out_hard = True
        LogEvent.account_locked_hard(self)

    def unlock_hard(self):
        self.locked_out_hard = False
        LogEvent.account_unlocked_hard(self)
        return self.unlock()

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
