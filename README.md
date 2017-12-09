# Welcome to my blog!
----

> This is a blog created in Python with Google App Engine. Users can create secure accounts, make posts, and comment on posts. Here is some information on how to get it running.

----
## Required Software
1. Install Python 2.7 if you haven't yet already. You can see if Python is working
by opening your console and typing `python --version`.

2. We use the Jinja2 environment to get our templates for this blog. You can install it
here: http://jinja.pocoo.org/docs/2.9/intro/

## Running the blog
1. In your console, change directories to the same directory this file is in.

2. Enter this into your console:    `dev_appserver.py .`

3. You should see something like this:


    INFO     2017-02-28 14:04:45,934 api_server.py:205] Starting API server at: http://localhost:62185
    INFO     2017-02-28 14:04:45,937 dispatcher.py:197] Starting module "default" running at: http://localhost:8080
    INFO     2017-02-28 14:04:45,938 admin_server.py:116] Starting admin server at:http://localhost:8000

You can see where the blog is being hosted, in this case: ```http://localhost:8080```

4.  Open your browser to the blog page. In this case, it would be ```http://localhost:8080/blog```.

5.  There is a link on the top of the page to create an account. Enjoy!

## Troubleshooting
It's important that you're using Python 2 and not Python 3.

If you run into any problems, check the Google App Engine documentation. They have guides to get an app running and can assist you with any problems.
https://cloud.google.com/appengine/docs/

Here are some tutorials that you may find helpful.
https://cloud.google.com/appengine/docs/standard/python/tutorials

