"""Flash message constants.

This module contains all of the string constants used for flash messages. The
attributes in the message classes should be tuples with two elements. The first
element is the message string. The second element is the message category. This
enables flash messages in each category to take on unique visual traits, by
passing a CSS class name behind the scenes. If you do not wish for a flash
message to be displayed for a particular event, set the attribute to None
instead of the standard tuple.

Message Classes:
    AuthMessages:   Messages used in "auth" blueprint.
    MainMessages:   Messages used in "main" blueprint.

Functions:
    flash_it:   Wrapper for Flask's flash function.

"""

from flask import flash
from .flash_category import FlashCategory


def flash_it(message_structure):
    if message_structure:
        flash(*message_structure)


class AuthMessages:
    ACCOUNT_CONFIRMED = (
        'Your account is confirmed',
        FlashCategory.SUCCESS
    )
    ACCOUNT_UNLOCKED = (
        'Your account is unlocked',
        FlashCategory.SUCCESS
    )
    CONFIRM_ACCOUNT = (
        'Check your email for confirmation instructions',
        FlashCategory.INFO
    )
    EMAIL_CHANGE_REQUEST = (
        'Confirmation instructions sent to the requested email',
        FlashCategory.INFO
    )
    EMAIL_UPDATED = (
        'Your email is updated',
        FlashCategory.SUCCESS
    )
    INVALID_CONFIRMATION_LINK = (
        'This link is invalid or has expired',
        FlashCategory.DANGER
    )
    INVALID_CREDENTIALS = (
        'Bad username or password',
        FlashCategory.DANGER
    )
    INVALID_PASSWORD = (
        'Bad password',
        FlashCategory.DANGER
    )
    INVALID_PASSWORD_RESET_LINK = (
        'Password not updated due to invalid or expired token',
        FlashCategory.DANGER
    )
    LOG_OUT = (
        'You have logged out',
        FlashCategory.SUCCESS
    )
    LOGIN_REQUIRED = (
        'Log in to access this page',
        FlashCategory.INFO
    )
    PASSWORD_UPDATED = (
        'Your password is updated',
        FlashCategory.SUCCESS
        )
    PASSWORD_RESET_REQUEST = (
        'Check your email for password reset instructions',
        FlashCategory.INFO
    )
    PASSWORD_RESET_REQUEST_DISABLED_ACCOUNT = (
        'Password reset not allowed for disabled accounts',
        FlashCategory.INFO
    )
    REFRESH_REQUIRED = (
        'Verify your password to continue',
        FlashCategory.INFO
    )
    SESSION_EXPIRED = (
        'Your session has expired',
        FlashCategory.DANGER
    )
    USERNAME_UPDATED = (
        'Your username is updated',
        FlashCategory.SUCCESS
    )


class MainMessages:
    PROFILE_UPDATED = (
        'Your profile is updated',
        FlashCategory.SUCCESS
    )
    OTHER_PROFILE_UPDATED = (
        'The profile is updated',
        FlashCategory.SUCCESS
    )
