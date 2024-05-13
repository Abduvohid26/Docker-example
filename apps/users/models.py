from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken
ADMIN, MANAGER, ORDINARY_USER = ('admin', 'manager', 'ordinary_user')


class User(AbstractUser):
    USER_ROLES = (
        (ADMIN, ADMIN),
        (MANAGER, MANAGER),
        (ORDINARY_USER, ORDINARY_USER),
    )
    user_roles = models.CharField(max_length=50, choices=USER_ROLES, default=ORDINARY_USER)

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh_token': str(refresh.refresh_token),
            'access_token': str(refresh.access_token),
        }

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'

    def check_hash_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)

    def __str__(self):
        return f'{self.username} {self.user_roles}'

    def save(self, *args, **kwargs):
        self.check_hash_password()
        super(User, self).save(*args, **kwargs)


