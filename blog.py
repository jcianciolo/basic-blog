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
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

secret = 'coolranch'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
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

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    respose.out.write(post.content)

class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()


    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name=  name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# blog stuff

def blog_key(name = 'defaultc'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    liked = db.StringListProperty()
    last_modifed = db.DateTimeProperty(auto_now = True)
    author = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Comment(db.Model):
    comment_content = db.TextProperty(required=True)
    comment_created = db.DateTimeProperty(auto_now_add=True)
    parent_post = db.ReferenceProperty(Post, collection_name="comments")
    comment_author = db.TextProperty()


class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("SELECT * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

    def post(self):
        new_post_button = self.request.get('newpost-button')

        if new_post_button:
            return self.redirect('/blog/newpost')

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)
        hidden = self.request.get('hidden')

        if not post:
            return self.redirect('/blog')

        self.render("permalink.html", post = post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)
        if not post:
            return self.redirect('/blog')

        comment_content = self.request.get('comment_content')
        comment_button = self.request.get('comment_button')

### Comment button only appears to logged in users.
### This authentication check is in 'permalink.html', line 46
        if self.user:
            if comment_button:
                if comment_content:
                    parent_post = post.key().id()     # references the correct post
                    comment_author = self.user.name
                    c = Comment(parent = blog_key(), comment_content=comment_content,
                        parent_post=post, comment_author=comment_author)
                    c.put()
                    return self.redirect('/blog/%s' % str(post.key().id()))

                elif comment_button and not comment_content:
                    error = "Please enter a comment first!"
                    self.render("permalink.html", post = post, error = error)

            else:
                error = "You are not the author of this post!"
                self.render("permalink.html", post = post, error = error)

        else:
            error = "You must be logged in to do that!"
            self.render("permalink.html", post = post, error = error)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = author)
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject = subject, content = content, author = author, error = error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        login_button = self.request.get('login-button')

        if login_button:
            return self.redirect('/login')

        params = dict(username = self.username, email = self.email)

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
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #check that the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            return self.redirect('/unit3/welcome')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            return self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            return self.redirect('/unit2/signup')

class EditPostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)

        if not post:
            return self.redirect('/blog')

        if not self.user:
            return self.redirect('/login')

        if self.user.name == post.author:
            self.render("edit-form.html", post = post)
        else:
            return self.redirect('/blog/%s' % post.key().id())

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)

        if not post:
            return self.redirect('/blog')
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if self.user.name == post.author:
            if subject and content:
                edit = Post.get_by_id(int(post_id), parent=blog_key())
                edit.subject = subject
                edit.content = content
                edit.put()
                return self.redirect('/blog/%s' % str(edit.key().id()))
            else:
                error = "subject and content please!"
                self.render("edit-form.html", subject = subject, content = content, error = error, post = post)
        else:
            return self.redirect('/blog')

class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)
        c = Comment.get_by_id(int(comment_id), parent=blog_key())

        if not self.user:
            return self.redirect('/login')

        if not post or not c:
            return self.redirect('/blog')

        if self.user.name == c.comment_author:
            self.render("edit-comment.html", c = c, post = post)
        else:
            return self.redirect('/blog/%s' % int(post_id))

    def post(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)
        c = Comment.get_by_id(int(comment_id), parent=blog_key())
        comment_content = self.request.get('content')

        if not self.user:
            return self.redirect('/login')

        if not post or not c:
            return self.redirect('/blog')

        if self.user.name == c.comment_author:
            if comment_content:
                edit_comment = Comment.get_by_id(int(comment_id), parent=blog_key())
                edit_comment.comment_content = comment_content
                edit_comment.put()
                return self.redirect('/blog/%s' % post.key().id())
            elif not comment_content:
                error = "Please enter a comment in the comment field! Or, press cancel to go back."
                self.render("edit-comment.html", c = c, post = post, error = error)
        else:
            return self.redirect('/blog')

class DeletePostPage(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            return self.redirect('/blog')

# This code prevents users from simply typing /blog/delete/ + post URL
# without being the author
        if self.user:
            if self.user.name == post.author:
                post.delete()
                return self.redirect('/blog')
            else:
                return self.redirect('/blog')
        else:
            return self.redirect('/login')

class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        c = Comment.get_by_id(int(comment_id), parent=blog_key())

        if not self.user:
            return self.redirect('/login')

        if not c or not post:
            return self.redirect('/blog')

        if self.user.name == c.comment_author:
            c.delete()
            return self.redirect('/blog/%s' % post.key().id())
        elif self.user.name != c.comment_author:
            return self.redirect('/blog/%s' % post.key().id())

    def post(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        c = Comment.get_by_id(int(comment_id), parent=blog_key())

        if not self.user:
            return self.redirect('/login')

        if not c or not post:
            return self.redirect('/blog')

        if self.user.name == c.comment_author:
            c.delete()
            return self.redirect('/blog/%s' % post.key().id())
        elif self.user.name != c.comment_author:
            return self.redirect('/blog/%s' % post.key().id())

class Votes(BlogHandler):
### Like/unlike button only appears to logged in users that are not the post's author.
### This authentication check is in 'permalink.html', line 29-30
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)

        if not post:
            return self.redirect('/blog')

        if self.user and self.user.name != post.author:
            if self.user.name not in post.liked:
                post.liked.append(self.user.name)
                post.put()
                return self.redirect('/blog/%s' % str(post.key().id()))
            elif self.user.name in post.liked:
                post.liked.remove(self.user.name)
                post.put()
                return self.redirect('/blog/%s' % str(post.key().id()))
        else:
            return self.redirect('/blog/%s' % str(post.key().id()))

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/edit/([0-9]+)', EditPostPage),
                               ('/blog/votes/([0-9]+)', Votes),
                               ('/blog/delete/([0-9]+)', DeletePostPage),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/([0-9]+)/EditComment/([0-9]+)', EditComment),
                               ('/blog/([0-9]+)/DeleteComment/([0-9]+)', DeleteComment),
                               ],
                              debug=True)
