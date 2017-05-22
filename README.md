# GAE Multi User Blog

*Program:* Udacity Full Stack Web Developer Nanodegree
*Project 3:* Multi User Blog
*Languages:* Python, HTML, CSS, JS, GAE

# Getting Started

## Dependencies

This documentations was written to run on *Windows 10* using *Git* and *Python 2.7.x* and requires an active internet connection to run properly. It may work on other operating systems but the developer makes no guarantees.

Libraries included in this project are:
- Source code from Full Stack Nanodegree Web Application Homework 4 used for reference
- Html5Boilerplate used for starting template
- Bootstrap used for styling
- jQuery used for styling
- Google Appengine SDK

## Installation and Launch

In order to download and run a copy of this code on your local machine please follow the code below as well as having Git and Google Appengine SDK installed:
```
git clone https://github.com/connormckinnon93/udacityMultiUserBlog.git
cd udacityMultiUserBlog
npm install
dev_appserver.py .
```

If you want to update the styles you should run `gulp`.

If you want to deploy and then view on Google Appengine you should run the following code:
```
gcloud app deploy
gcloud app brows
```

## Known Bugs
This is the list of known issues:
- Google Appengine uses a consistent modelling which means you can't easily redirect to main page following a delete and have the delete register immediately (hence the confirmation page)
- The gulpfile uses concatenation to minimize CSS and JS but the order can cause cascading errors and required an `!important` attribute to fix it