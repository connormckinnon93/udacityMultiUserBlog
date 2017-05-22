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

import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Secret is imported from the environment variable in app.yaml
secret = os.getenv('SECRET', 'default_secret')


# render_str is used in the Handler class
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# USER STUFF
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pw(name, password, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# BLOG STUFF
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user_id = db.StringProperty(required=True)
    user_name = db.StringProperty()
    likes = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("partials/post.html", p=self)


class Like(db.Model):
    user_id = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    
    @classmethod
    def by_user_post(cls, user_id, post_id):
        l = Like.all().filter('user_id =', user_id).filter('post_id =', post_id).get()
        return l


class Comment(db.Model):
    user_id = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("partials/comment.html", c=self)

# Handler serves as a parent to all page controllers
class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
    
    def check_for_user(self):
        if self.user:
            user_id = str(self.user.key().id())
            return user_id
        else:
            user_id = ""
            return False

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(Handler):

    def get(self):
        posts = Post.all().order('-created')
        self.render('index.html', posts=posts)


class SubmitPostPage(Handler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect('/login')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        user_id = str(self.user.key().id())
        user_name = self.user.name

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     likes=0, user_id=user_id, user_name=user_name)
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)



def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)

def find_post(post_id):
    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
    post = db.get(key)
    return post

def find_comment(comment_id):
    key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
    comment = db.get(key)
    return comment

class ViewPostPage(Handler):

    def get(self, post_id):
        post = find_post(post_id)
        comments = Comment.all().filter('post_id =', post_id).order('-created')
        if not post:
            self.error(404)
            return

        if not comments:
            comments = ""

        self.render("permalink.html", post=post, comments=comments)

class Controller(Handler):

    def secure_interaction(self, id, item_type="Post", error_type="delete", match_user=True):
        if item_type == "Post":
            item = find_post(id)
        elif item_type == "Comment":
            item = find_comment(id)
        else:
            self.error(404)
            return

        created_by = item.user_id
        modified_by = self.check_for_user()

        if not modified_by:
            self.redirect('/login')
            return
        else:
            if match_user and (created_by == modified_by):
                return item
            elif not match_user and (created_by != modified_by):
                return item
            else:
                self.render('error.html', error=error_type)



class CommentController(Handler):

    def get(self, post_id):
        post = find_post(post_id)

        if self.check_for_user():
            self.render("newcomment.html", post=post)
        else:
            self.redirect('/login')

    def post(self, post_id):
        content = self.request.get('content')
        user_id = self.check_for_user()

        if user_id:
            c = Comment(parent=blog_key(), user_id=user_id,
                        post_id=post_id, content=content)
            c.put()
            self.redirect('/post/%s' % post_id)
        else:
            self.redirect('/login')


class DeleteController(Controller):

    def post(self, post_id):
        post = self.secure_interaction(post_id)
        if post:
            post.delete()
            self.redirect('/')


class LikeController(Controller):

    def post(self, post_id):
        # TODO: Fix NoneType error and instead have it render error.html with error
        post = self.secure_interaction(post_id, error_type="like", match_user=False)
        if post:
            user_id = self.check_for_user()
            like = Like.by_user_post(user_id, str(post.key().id()))
            if like:
                post.likes -= 1
                like.delete()
                post.put()
            else:
                post.likes += 1
                l = Like(parent=blog_key(), user_id=user_id,
                         post_id=str(post.key().id()))
                l.put()
                post.put()

            self.redirect('/post/%s' % str(post.key().id()))
        else:
            self.redirect('/')


class EditController(Handler):

    def get(self, post_id):
        post = find_post(post_id)
        created_by = post.user_id
        edited_by = self.check_for_user()

        if edited_by:
            if edited_by == created_by:

                if not post:
                    self.error(404)
                    return
                else:
                    self.render("edit.html", post=post)
            else:
                self.render('error.html', error='edit')
        else:
            self.redirect('/login')

    def post(self, post_id):
        post = find_post(post_id)
        created_by = post.user_id
        edited_by = self.check_for_user()

        if edited_by:
            if edited_by == created_by:
                if not post:
                    self.error(404)
                    return
                else:
                    subject = self.request.get('subject')
                    content = self.request.get('content')

                    if subject and content:
                        post.subject = subject
                        post.content = content
                        post.put()
                        self.redirect('/post/%s' % str(post.key().id()))
                    else:
                        error = "subject and content, please!"
                        self.render("edit.html", subject=subject,
                                    content=content, error=error)
            else:
                self.render('error.html', error='edit')
        else:
            self.redirect('/login')


class EditCommentController(Handler):

    def get(self, comment_id):
        comment = find_comment(comment_id)
        created_by = comment.user_id
        edited_by = self.check_for_user()

        if edited_by:
            if edited_by == created_by:

                if not comment:
                    self.error(404)
                    return
                else:
                    self.render("editcomment.html", comment=comment)
            else:
                self.render('error.html', error='edit')
        else:
            self.redirect('/login')

    def post(self, comment_id):
        comment = find_comment(comment_id)
        created_by = comment.user_id
        edited_by = self.check_for_user()

        if self.user:
            edited_by = str(self.user.key().id())

            if edited_by == created_by:
                if not comment:
                    self.error(404)
                    return
                else:
                    content = self.request.get('content')

                    if content:
                        comment.content = content
                        comment.put()
                        self.redirect('/post/%s' % str(comment.post_id))
                    else:
                        error = "content, please!"
                        self.render("editcomment.html",
                                    content=content, error=error)
            else:
                self.render('error.html', error='edit')
        else:
            self.redirect('/login')

class DeleteCommentController(Handler):

    def post(self, comment_id):
        comment = find_comment(comment_id)
        created_by = comment.user_id
        deleted_by = self.check_for_user()

        if deleted_by:
            if deleted_by == created_by:

                if not comment:
                    self.error(404)
                    return
                else:
                    comment.delete()

                self.redirect('/user')
            else:
                self.render('error.html', error='delete')
        else:
            self.redirect('/login')

class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

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

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class RegisterPage(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/user')


class UserPage(Handler):

    def get(self):
        user_id = self.check_for_user()
        if user_id:
            posts = Post.all().filter('user_id =', user_id).order('-created')
            self.render('welcome.html', username=self.user.name, posts=posts)
        else:
            self.redirect('/signup')


class LoginPage(Handler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/user')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/signup')


class ErrorHandler(Handler):

    def get(self):
        self.render('error.html')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', SubmitPostPage),
                               ('/post/([0-9]+)', ViewPostPage),
                               ('/post/([0-9]+)/delete', DeleteController),
                               ('/post/([0-9]+)/comment', CommentController),
                               ('/comment/([0-9]+)/edit', EditCommentController),
                               ('/comment/([0-9]+)/delete', DeleteCommentController),
                               ('/post/([0-9]+)/edit', EditController),
                               ('/post/([0-9]+)/like', LikeController),
                               ('/signup', RegisterPage),
                               ('/user', UserPage),
                               ('/login', LoginPage),
                               ('/logout', Logout)], debug=True)
