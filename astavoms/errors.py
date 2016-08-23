# Copyright 2016 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


class AstavomsRESTError(Exception):
    """Template class for Astavoms errors"""
    status_code = None  # Must be set

    def __init__(self, message=None, status_code=None, payload=None):
        """ Add some context to the error
            :param message: a user friendly message
            :param status_code: REST status code
            :param payload: (dict) some context for the error
        """
        Exception.__init__(self)
        self.message = message or self.__doc__
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        """Return errors in JSON instead of the default HTML format"""
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


class AstavomsInputIsMissing(AstavomsRESTError):
    """Request is missing data input"""
    status_code = 400  # Bad request


class AstavomsInvalidInput(AstavomsRESTError):
    """Input is missing some elements"""
    status_code = 400  # Bad request


class AstavomsInvalidProxy(AstavomsRESTError):
    """Client proxy certificates are not well formated or missing"""
    status_code = 400  # Bad request


class AstavomsUnknownVO(AstavomsRESTError):
    """Virtual Organization not in dictionary"""
    status_code = 400  # Bad request


class AstavomsProjectError(AstavomsRESTError):
    """Failed to enroll user to project"""
    status_code = 400  # Unauthorized


class AstavomsUnauthorizedVOMS(AstavomsRESTError):
    """VOMS Authentication Failed"""
    status_code = 401  # Unauthorized


class AstavomsInvalidToken(AstavomsRESTError):
    """This token does not match with any Astavoms users"""
    status_code = 401  # Unauthorized


class AstavomsSynnefoError(AstavomsRESTError):
    """Synnefo Error"""
    status_code = 500  # Internal Server Error

    def __init__(
            self, message=None, status_code=500, payload=dict(), error=None):
        if error:
            snf_status = getattr(error, 'status', '')
            message = message or 'SNF: {err} {status}'.format(
                err=error, status=snf_status)
            payload = payload.update(dict(
                type=error, error='{0}'.format(error), snf_status=snf_status))
            status_code = snf_status or status_code
        AstavomsRESTError.__init__(self, message, status_code, payload)
