import unittest
import time
from datetime import datetime, timedelta
from app import create_app, db
from app.models import User, AnonymousUser, Role, Permission, AccountPolicy


class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_setter(self):
        u = User(password='cat')
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):
        u = User(password='cat')
        with self.assertRaises(AttributeError):
            u.password

    def test_password_verification(self):
        u = User(password='cat')
        self.assertTrue(u.verify_password('cat'))
        self.assertFalse(u.verify_password('dog'))

    def test_password_salts_are_random(self):
        u = User(password='cat')
        u2 = User(password='cat')
        self.assertTrue(u.password_hash != u2.password_hash)

    def test_valid_confirmation_token(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token()
        self.assertTrue(u.confirm(token))

    def test_invalid_confirmation_token(self):
        u1 = User(password='cat')
        u2 = User(password='dog')
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()
        token = u1.generate_confirmation_token()
        self.assertFalse(u2.confirm(token))

    def test_expired_confirmation_token(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_confirmation_token(1)
        time.sleep(2)
        self.assertFalse(u.confirm(token))

    def test_valid_reset_token(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_reset_token()
        self.assertTrue(u.reset_password(token, 'dog'))
        self.assertTrue(u.verify_password('dog'))

    def test_invalid_reset_token(self):
        u1 = User(password='cat')
        u2 = User(password='dog')
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()
        token = u1.generate_reset_token()
        self.assertFalse(u2.reset_password(token, 'horse'))
        self.assertTrue(u2.verify_password('dog'))

    def test_valid_email_change_token(self):
        u = User(email='john@example.com', password='cat')
        db.session.add(u)
        db.session.commit()
        token = u.generate_email_change_token('susan@example.org')
        self.assertTrue(u.change_email(token))
        self.assertTrue(u.email == 'susan@example.org')

    def test_invalid_email_change_token(self):
        u1 = User(email='john@example.com', password='cat')
        u2 = User(email='susan@example.org', password='dog')
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()
        token = u1.generate_email_change_token('david@example.net')
        self.assertFalse(u2.change_email(token))
        self.assertTrue(u2.email == 'susan@example.org')

    def test_duplicate_email_change_token(self):
        u1 = User(email='john@example.com', password='cat')
        u2 = User(email='susan@example.org', password='dog')
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()
        token = u2.generate_email_change_token('john@example.com')
        self.assertFalse(u2.change_email(token))
        self.assertTrue(u2.email == 'susan@example.org')

    def test_roles_and_permissions(self):
        u = User(email='john@example.com', password='cat')
        self.assertTrue(u.can(Permission.WRITE_ARTICLES))
        self.assertFalse(u.can(Permission.MODERATE_COMMENTS))

    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.FOLLOW))

    def test_timestamps(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        self.assertTrue(
            (datetime.utcnow() - u.member_since).total_seconds() < 3)
        self.assertTrue(
            (datetime.utcnow() - u.last_seen).total_seconds() < 3)

    def test_ping(self):
        u = User(password='cat')
        db.session.add(u)
        db.session.commit()
        time.sleep(2)
        last_seen_before = u.last_seen
        u.ping()
        self.assertTrue(u.last_seen > last_seen_before)

    def test_gravatar(self):
        u = User(email='john@example.com', password='cat')
        with self.app.test_request_context('/'):
            gravatar = u.gravatar()
            gravatar_256 = u.gravatar(size=256)
            gravatar_pg = u.gravatar(rating='pg')
            gravatar_retro = u.gravatar(default='retro')
        with self.app.test_request_context('/', base_url='https://example.com'):
            gravatar_ssl = u.gravatar()
        self.assertTrue('http://www.gravatar.com/avatar/' +
                        'd4c74594d841139328695756648b6bd6'in gravatar)
        self.assertTrue('s=256' in gravatar_256)
        self.assertTrue('r=pg' in gravatar_pg)
        self.assertTrue('d=retro' in gravatar_retro)
        self.assertTrue('https://secure.gravatar.com/avatar/' +
                        'd4c74594d841139328695756648b6bd6' in gravatar_ssl)

    def test_auth_token(self):
        u = User(email='john@example.com', username='john', password='cat')
        self.assertIsNotNone(u.auth_token)

    def test_auth_token_changes_when_email_is_updated(self):
        u = User(email='john@example.com', username='john', password='cat')
        old_auth = u.auth_token
        change_email_token = u.generate_email_change_token('fred@example.com')
        u.change_email(change_email_token)
        self.assertNotEqual(old_auth, u.auth_token)

    def test_auth_token_changes_when_password_is_updated(self):
        u = User(email='john@example.com', username='john', password='cat')
        old_auth = u.auth_token
        u.password = 'cat'
        self.assertNotEqual(old_auth, u.auth_token)

    def test_auth_token_changes_when_username_is_updated(self):
        u = User(email='john@example.com', username='john', password='cat')
        old_auth = u.auth_token
        u.change_username('cooldude')
        self.assertNotEqual(old_auth, u.auth_token)

    def test_new_user_account_not_locked_out(self):
        u = User(email='john@example.com', username='john', password='cat')
        db.session.add(u)
        db.session.commit()
        self.assertFalse(u.locked)

    def test_account_lockout_threshold(self):
        u = User(email='john@example.com', username='john', password='cat')
        db.session.add(u)
        db.session.commit()
        for i in range(AccountPolicy.LOCKOUT_THRESHOLD):
            u.verify_password('dog')
        self.assertTrue(u.locked)

    def test_account_lockout_reset_duration(self):
        seconds = 3
        AccountPolicy.RESET_THRESHOLD_AFTER = timedelta(seconds=seconds)
        u = User(email='john@example.com', username='john', password='cat')
        db.session.add(u)
        db.session.commit()
        for i in range(AccountPolicy.LOCKOUT_THRESHOLD - 1):
            u.verify_password('dog')
        time.sleep(seconds)
        u.verify_password('dog')
        self.assertFalse(u.locked)
        self.assertEquals(u.failed_login_attempts, 1)

    def test_auth_token_changes_after_lockout(self):
        u = User(email='john@example.com', username='john', password='cat')
        db.session.add(u)
        db.session.commit()
        old_auth = u.auth_token
        for i in range(AccountPolicy.LOCKOUT_THRESHOLD):
            u.verify_password('dog')
        self.assertTrue(u.locked)
        self.assertNotEqual(old_auth, u.auth_token)

    def test_account_unlock_succeeds(self):
        u = User(email='john@example.com', username='john', password='cat')
        db.session.add(u)
        db.session.commit()
        for i in range(AccountPolicy.LOCKOUT_THRESHOLD):
            u.verify_password('dog')
        self.assertTrue(u.locked)
        u.locked = False
        self.assertFalse(u.locked)

    def test_user_registration_succeeds_up_to_max_users_then_fails(self):
        for i in range(self.app.config['APP_MAX_USERS']):
            self.assertTrue(User.can_register())
            email = 'u%s@test.com' % i
            username = 'u%s' % i
            u = User(email=email, username=username, password='cat')
            db.session.add(u)
            db.session.commit()
        self.assertFalse(User.can_register())

    def test_user_registration_fails_when_not_allowing_new_users(self):
        self.app.config['APP_ALLOW_NEW_USERS'] = False
        self.assertFalse(User.can_register())

    def test_new_user_account_is_enabled(self):
        u = User(password='cat')
        self.assertTrue(u.enabled)

    def test_verify_password_fails_when_account_is_disabled(self):
        u = User(password='cat')
        u.enabled = False
        self.assertFalse(u.verify_password('cat'))

    def test_verify_password_fails_when_account_is_locked(self):
        u = User(password='cat')
        u.locked = True
        self.assertFalse(u.verify_password('cat'))
