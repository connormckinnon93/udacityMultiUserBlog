# Import Required Libraries for this Blog Application
import os
# Import Required Libraries for Templating and Web Routing
import jinja2


# Simplify the templating process with jinja2 and a route to the template_dir
template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# render_str is used in the Handler class
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)