# Import from google.appengine library for interacting with DataStore
from google.appengine.ext import db

# Create Like instance to create a one-to-one relationship between users and posts
class Like(db.Model):
    user_id = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)

    # Return a like object based on user_id and post_id
    @classmethod
    def by_user_post(cls, user_id, post_id):
        l = Like.all().filter('user_id =',
                              user_id).filter('post_id =', post_id).get()
        return l