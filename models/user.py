# Import from google.appengine library for interacting with DataStore
from google.appengine.ext import db

# Define ancestor for users, allow for possibility of multiple groups later
def users_key(group='default'):
    return db.Key.from_path('users', group)

# Create user instance in DataStore
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # Retrieve User by ID
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    # Retrieve User by Name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    # Create User and add pw_hash
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    # Login using by name
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u