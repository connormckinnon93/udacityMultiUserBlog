# Import from google.appengine library for interacting with DataStore
from google.appengine.ext import db
from utils import render_str

# Create Comment instance in DataStore, associated with Post and User
class Comment(db.Model):
    user_id = db.StringProperty(required=True)
    user_name = db.StringProperty()
    post_id = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    # Render the comment using same technique as post
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("partials/comment.html", c=self)
