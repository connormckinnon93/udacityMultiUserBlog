# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Import Required Libraries for this Blog Application
import os
import re
import random
import hashlib
import hmac
from string import letters

# Import Required Libraries for Templating and Web Routing
import webapp2
import jinja2

# Import from google.appengine library for interacting with DataStore
from google.appengine.ext import db

from models import Like
from models import Post
from models.utils import render_str

# Simplify the templating process with jinja2 and a route to the template_dir
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Secret is imported from the environment variable in app.yaml
secret = os.getenv('SECRET', 'default_secret')
debug = os.getenv('DEBUG', True)


# Create a secure value using hmac (used in Cookies)
def make_secure_val(val):
    # Use pipe to avoid an issue with GAE and imported secret
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# User make_secure_val to compare values and return the value if the hash works


def check_secure_val(secure_val):
    # Split at pipe to find value
    val = secure_val.split('|')[0]
    # if you can recreate the hash return the value
    if secure_val == make_secure_val(val):
        return val

# USER STUFF
# Make salt, can increase complexit by increasing default length


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

# Make a pw hash using sha256 and salt used in registering users and signing in


def make_pw_hash(name, pw, salt=None):
    # If there is no existing salt make one
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    # use pipe to avoid issues in GAE
    return '%s|%s' % (h, salt)

# Validate a pw hash and


def valid_pw(name, password, h):
    # split at pipe
    salt = h.split('|')[1]
    return h == make_pw_hash(name, password, salt)

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


# BLOG STUFF
# Define ancestor to blog objects, add option to create other groups later
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# Handler serves as a parent to all page controllers


class Handler(webapp2.RequestHandler):

    # Shorthand for the response.out.write of the WSIG app
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # Render the string and make the user available throughout
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    # Combine above methods in order to safely render template
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Set a secure cookie value using make_secure_val
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Read the cookie value and check the value using check_secure_val
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Log the user in and set an appropriate cookie
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Log the user out and remove the set cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Check the user and return false if none is found
    def check_for_user(self):
        if self.user:
            user_id = str(self.user.key().id())
            return user_id
        else:
            user_id = ""
            return False

    # Set initialize and add self.user to the user_id
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# MainPage inherits from handler and shows index, sits at root


class MainPage(Handler):

    def get(self):
        # get all posts and order by date created
        posts = Post.all().order('-created')
        self.render('index.html', posts=posts)

# SubmitPostPage inherits from handler, and deals with creating posts


class SubmitPostPage(Handler):

    # GET returns the form to submit a post if someone is logged in
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            # Redirect to login if no user logged in
            self.redirect('/login')

    # POST creates a new Post object
    def post(self):
        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            user_id = str(self.user.key().id())
            user_name = self.user.name

            # If subject and contnet are present create post
            if subject and content:
                p = Post(parent=blog_key(), subject=subject, content=content,
                         likes=0, user_id=user_id, user_name=user_name)
                p.put()
                self.redirect('/post/%s' % str(p.key().id()))
            else:
                # Render the form again with error notification if missing
                # information
                error = "subject and content, please!"
                self.render("newpost.html", subject=subject,
                            content=content, error=error)
        else:
            # Redirect to login if no user logged in
            self.redirect('/login')

# Use Regex to validate username


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)

# Use Regex to validate password


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)

# Use Regex to validate email


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)

# Function to return a post using post_id


def find_post(post_id):
    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
    post = db.get(key)
    if not post:
        return False
    else:
        return post

# Function to return a comment using comment_id


def find_comment(comment_id):
    key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
    comment = db.get(key)
    if not comment:
        return False
    else:
        return comment

# ViewPostPage inherits form handler, shows invidiual posts and comments


class ViewPostPage(Handler):

    def get(self, post_id):
        post = find_post(post_id)
        # return all comments associated with this post
        comments = Comment.all().filter('post_id =', post_id).order('-created')
        if not post:
            self.error(404)
            return

        # Prevent NoneType error with null string
        if not comments:
            comments = ""

        self.render("permalink.html", post=post, comments=comments)

# Base class for ensuring that person interacting with content has
# permission too


class Controller(Handler):

    # method for securing interactions, defaults to posts, deleting, and making sure
    # that the person who interacts with the content is the owner
    def secure_interaction(self, id, item_type="Post",
                           error_type="delete", match_user=True):
        # Find the post or comment
        if item_type == "Post":
            item = find_post(id)
        elif item_type == "Comment":
            item = find_comment(id)
        else:
            self.error(404)
            return

        if not item:
            self.error(404)
            return

        # Save the owner of the item
        if item.user_id:
            created_by = item.user_id
        else:
            created_by = False
        # Find the person trying to modify the item
        modified_by = self.check_for_user()

        # If not logged in direct them to login form
        if not modified_by:
            self.redirect('/login')
            return
        else:
            # for everything except likes check created is same as modified
            if match_user and (created_by == modified_by):
                return item
            # for likes check created is not the same as modified
            # can't like your own post
            elif not match_user and (created_by != modified_by):
                return item
            else:
                # render error screen with appropriate message
                self.render('error.html', error=error_type)

# CommentController inherits from Controller and deals with comments


class CommentController(Controller):

    # GET render comment form
    def get(self, post_id):
        post = self.secure_interaction(post_id)
        if post:
            self.render("newcomment.html", post=post)

    # POST inserts a new comment associated with a post
    def post(self, post_id):
        # Retrieve required information
        post = self.secure_interaction(post_id)
        content = self.request.get('content')
        user_id = self.check_for_user()
        user_name = self.user.name

        # Ensure content was submitted with comment and return error if not
        if content:
            c = Comment(parent=blog_key(), user_id=user_id,
                        user_name=user_name, post_id=post_id, content=content)
            c.put()
            self.redirect('/post/%s' % post_id)
        else:
            self.render("newcomment.html", post=post, error="Required content")

# DeleteController inherits from controller and handles the deletion of posts


class DeleteController(Controller):

    # POST deletes post if created and modified match
    def post(self, post_id):
        post = self.secure_interaction(post_id)
        if post:
            post.delete()
            username = self.user.name
            self.render('confirmation.html', username=username)

# LikeController inherits from controller and handles the liking of posts


class LikeController(Controller):

    # POST creates a like instance for posts
    def post(self, post_id):
        # Prevent users from liking their own posts
        post = self.secure_interaction(
            post_id, error_type="like", match_user=False)
        if post:
            user_id = self.check_for_user()
            # Determine if the user has liked the post before
            like = Like.by_user_post(user_id, str(post.key().id()))
            # If they have liked the post before remove the like and decrease
            # the post likes
            if like:
                post.likes -= 1
                like.delete()
                post.put()
            else:
                # If they have not liked the post before then add a like and
                # increase the post likes
                post.likes += 1
                l = Like(parent=blog_key(), user_id=user_id,
                         post_id=str(post.key().id()))
                l.put()
                post.put()

            self.redirect('/post/%s' % str(post.key().id()))

# EditController inherits from controller and manages the editing of posts


class EditController(Controller):

    # GET opens the edit form if permissions allow
    def get(self, post_id):
        post = self.secure_interaction(post_id, error_type="edit")
        if post:
            self.render("edit.html", post=post)

    # POST edits the post if permissions allow
    def post(self, post_id):
        post = self.secure_interaction(post_id, error_type="edit")
        if post:
            subject = self.request.get('subject')
            content = self.request.get('content')

            # check for content and create a new post object
            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/post/%s' % str(post.key().id()))
            else:
                # return an error if they are missing one
                error = "subject and content, please!"
                self.render("edit.html", subject=subject,
                            content=content, error=error)

# EditCommentController inherits form controller and manages the editing
# of comments


class EditCommentController(Controller):

    # GET return the edit form if permissions allow
    def get(self, comment_id):
        comment = self.secure_interaction(
            comment_id, item_type="Comment", error_type="edit")
        if comment:
            self.render("editcomment.html", comment=comment)

    # POST updates the comment object if permissions allow
    def post(self, comment_id):
        comment = self.secure_interaction(
            comment_id, item_type="Comment", error_type="edit")
        if comment:
            content = self.request.get('content')

            # Check for content then if present update value
            if content:
                comment.content = content
                comment.put()
                self.redirect('/post/%s' % str(comment.post_id))
            else:
                # If content is empty return to form and display error
                error = "content, please!"
                self.render("editcomment.html",
                            content=content, error=error)

# DeleteCommentController inherits from controller and handles deleting
# comments


class DeleteCommentController(Controller):

    # POST checks for comment and authorization if approved it is deleted
    def post(self, comment_id):
        comment = self.secure_interaction(
            comment_id, item_type="Comment", error_type="delete")
        if comment:
            comment.delete()
            self.redirect('/post/%s' % str(comment.post_id))

# Signup inherits from Handler and provides some functionality for
# registering users


class Signup(Handler):

    # GET returns signup page
    def get(self):
        self.render("signup.html")

    # POST gathers information to signup a user
    def post(self):
        # initally there is no error
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        # save information in a dictionary list
        params = dict(username=self.username,
                      email=self.email)

        # validate information and raise error if regex fails
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        # if there is an error return to the isgnup apge with error information
        if have_error:
            self.render('signup.html', **params)
        else:
            # call done method which is implemented in RegisterPage class
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


# RegisterPage inherits from Signup and handles registering users
class RegisterPage(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            # raise error if user already exists
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            # add user to datastore
            u = User.register(self.username, self.password, self.email)
            u.put()

            # log the user in
            self.login(u)
            self.redirect('/user')


# UserPage inherits from handler and show the user page
class UserPage(Handler):

    def get(self):
        user_id = self.check_for_user()
        # see if the user is signed in
        if user_id:
            # get all posts associated with the signed in user
            posts = Post.all().filter('user_id =', user_id).order('-created')
            self.render('welcome.html', username=self.user.name, posts=posts)
        else:
            self.redirect('/signup')

# LoginPage inherits from handler and handles loging a user in


class LoginPage(Handler):

    # GET login form
    def get(self):
        self.render('login.html')

    # POST logs the user in
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # Use the login method on user entity to login
        u = User.login(username, password)

        # if successful redirect to user page
        if u:
            self.login(u)
            self.redirect('/user')
        else:
            # if unsuccessful then redirect to login form and show error msg
            msg = 'Invalid login'
            self.render('login.html', error=msg)

# Logout inherits from handler class and handles loging a user out


class Logout(Handler):

    def get(self):
        self.logout()
        # redirect to signup after login
        self.redirect('/signup')

# Create the webapp and define the routes
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', SubmitPostPage),
                               ('/post/([0-9]+)', ViewPostPage),
                               ('/post/([0-9]+)/delete', DeleteController),
                               ('/post/([0-9]+)/comment', CommentController),
                               ('/comment/([0-9]+)/edit',
                                EditCommentController),
                               ('/comment/([0-9]+)/delete',
                                DeleteCommentController),
                               ('/post/([0-9]+)/edit', EditController),
                               ('/post/([0-9]+)/like', LikeController),
                               ('/signup', RegisterPage),
                               ('/user', UserPage),
                               ('/login', LoginPage),
                               ('/logout', Logout)], debug=debug)
