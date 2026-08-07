# web/
# Application infrastructure that used to live inline in app.py: CSRF, error
# handlers, before_request hooks, Jinja filters/globals, Flask-Login wiring and
# shared response helpers.
#
# Every module here exposes init_app(app) and is called from app.create_app().
# Registration ORDER MATTERS for the before_request hooks — see web/hooks.py.
