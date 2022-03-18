# -*- coding: utf-8 -*-

from flask import request, redirect, current_app

YEAR_IN_SECS = 31536000


class SSLify(object):
    """Secures your Flask App."""

    def __init__(self, app=None, age=YEAR_IN_SECS, subdomains=False, permanent=False):
        self.app = None
        if app is not None:
            self.app = app
            self.init_app(app, age, subdomains, permanent)

    def init_app(self, app, age=YEAR_IN_SECS, subdomains=False, permanent=False):
        """Configures the configured Flask app to enforce SSL."""
        self.hsts_age = age
        self.hsts_include_subdomains = subdomains
        self.permanent = permanent

        if app.config.get('USE_SSL', True):
            app.before_request(self.redirect_to_ssl)
            app.after_request(self.set_hsts_header)

    @property
    def hsts_header(self):
        """Returns the proper HSTS policy."""
        hsts_policy = 'max-age={0}'.format(self.hsts_age)

        if self.hsts_include_subdomains:
            hsts_policy += '; includeSubDomains'

        return hsts_policy

    def redirect_to_ssl(self):
        """Redirect incoming requests to HTTPS."""
        # Should we redirect?
        criteria = [
            request.is_secure,
            request.headers.get('X-Forwarded-Proto', 'http') == 'https'
        ]

        if not any(criteria):
            if request.url.startswith('http://'):
                url = request.url.replace('http://', 'https://', 1)
                code = 302
                if self.permanent:
                    code = 301
                r = redirect(url, code=code)

                return r

    def set_hsts_header(self, response):
        """Adds HSTS header to each response."""
        if request.is_secure:
            response.headers.setdefault('Strict-Transport-Security', self.hsts_header)
        return response
