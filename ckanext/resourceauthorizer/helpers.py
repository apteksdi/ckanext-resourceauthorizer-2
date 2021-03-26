# -*- coding: utf-8 -*-

import dominate.tags as dom_tags
from markupsafe import Markup, escape
import ckan.lib.helpers as helpers
from routes import url_for


class literal(Markup):
    """Represents an HTML literal.
    """
    __slots__ = ()

    @classmethod
    def escape(cls, s):
        if s is None:
            return Markup(u"")
        return super(literal, cls).escape(s)


def _preprocess_dom_attrs(attrs):
    """Strip leading underscore from keys of dict.
    This hack was used in `webhelpers` library for some attributes,
    like `class` that cannot be used because it special meaning in
    Python.
    """
    return {
        key.rstrip('_'): value
        for key, value in attrs.items()
        if value is not None
    }


def link_to(label, url, **attrs):
    attrs = _preprocess_dom_attrs(attrs)
    attrs['href'] = url
    if label == '' or label is None:
        label = url
    return literal(dom_tags.a(label, **attrs))


def linked_organization(org):
    organization = helpers.get_organization(org)
    if organization:
        return literal(u'{icon} {link}'.format(
            icon=helpers.icon_html(
                organization['image_display_url'], alt='', inline=False),
            link=link_to(organization['title'],
                         url_for(
                controller='organization',
                action='read',
                id=organization['name']))))
    return 'Not Existed'
