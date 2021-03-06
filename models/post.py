# Import from google.appengine library for interacting with DataStore
from google.appengine.ext import db
from utils import render_str

# Create post instance in DataStore, associateed with User
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user_id = db.StringProperty(required=True)
    user_name = db.StringProperty()
    likes = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    # Render the post using a template/partial replacing newlines with <br>
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("partials/post.html", p=self)