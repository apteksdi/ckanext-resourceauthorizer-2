#!/usr/bin/python
# -*- coding: utf-8 -*-
'''Resource authorizer commands

Usage:

    resourceauthorizer init-db
    - Create the resource_acl table in the database

    resourceauthorizer list-acl [{resource-id}]
    - lists resource acls

    resourceauthorizer show-acl {id}
    - shows information of the resource acl

    resourceauthorizer create-acl {resource-id} {auth-type} {auth-id} {permission}
    - creates a new resource acl

    resourceauthorizer delete-acl {id}
    - deletes the resource acl

    resourceauthorizer update-acl {id} {auth-type} {auth-id} {permission}
    - updates the resource acl
'''
import sys

import click

from ckan import model
from ckan.logic import get_action

from ckan.cli.cli import CkanCommand


@click.group()
def resourceauthorizer():
    u'''Perform commands in the resourceauthorizer.
    '''
    pass


@resourceauthorizer.command(u'initdb')
def setup_db():
    from ckanext.resourceauthorizer.model import setup as db_setup
    db_setup()
    print('resource_acl table created')
    print('')


@resourceauthorizer.command(u'list-acl')
@click.argument(u'resource-id', type=click.STRING, nargs=1)
def list_acl(resource_id):
    ckan_context = {
        'model': model,
        'session': model.Session,
        'ignore_auth': True
    }
    admin_user = get_action('get_site_user')(ckan_context, {})
    context = {
        'model': model,
        'session': model.Session,
        'user': admin_user['name'],
        'ignore_auth': True,
    }
    data_dict = { 
        'resource_id':  resource_id 
    }
    acls = get_action('resource_acl_list')(context, data_dict)
    for acl in acls:
        print_acl(acl)


@resourceauthorizer.command(u'show-acl')
@click.argument(u'resource-id', type=click.STRING, nargs=1)
def show_acl(resource_id):
    ckan_context = {
        'model': model,
        'session': model.Session,
        'ignore_auth': True
    }
    admin_user = get_action('get_site_user')(ckan_context, {})
    context = {
        'model': model,
        'session': model.Session,
        'user': admin_user['name'],
        'ignore_auth': True,
    }
    data_dict = { 
        'id':  resource_id 
    }
    acl = get_action('resource_acl_show')(context, data_dict)
    print_acl(acl)


@resourceauthorizer.command(u'create-acl')
@click.argument(u'resource-id', type=click.STRING, nargs=1)
@click.argument(u'auth-type', type=click.STRING, nargs=1)
@click.argument(u'auth-id', type=click.STRING, nargs=1)
@click.argument(u'permission', type=click.STRING, nargs=1)
def create_acl(resource_id, auth_type, auth_id, permission):
    ckan_context = {
        'model': model,
        'session': model.Session,
        'ignore_auth': True
    }
    admin_user = get_action('get_site_user')(ckan_context, {})
    context = {
        'model': model,
        'session': model.Session,
        'user': admin_user['name'],
        'ignore_auth': True,
    }
    data_dict = {
        'resource_id': resource_id,
        'auth_type': auth_type,
        'auth_id': auth_id,
        'permission': permission
    }
    acl = get_action('resource_acl_create')(context, data_dict)
    print_acl(acl)


@resourceauthorizer.command(u'delete-acl')
@click.argument(u'resource-id', type=click.STRING, nargs=1)
def delete_acl(resource_id):
    ckan_context = {
        'model': model,
        'session': model.Session,
        'ignore_auth': True
    }
    admin_user = get_action('get_site_user')(ckan_context, {})
    context = {
        'model': model,
        'session': model.Session,
        'user': admin_user['name'],
        'ignore_auth': True,
    }
    data_dict = { 
        'id':  resource_id 
    }
    get_action('resource_acl_delete')(context, data_dict)
    print('acl <%s> was deleted.' % data_dict['id'])
    print('')


@resourceauthorizer.command(u'update-acl')
@click.argument(u'resource-id', type=click.STRING, nargs=1)
@click.argument(u'auth-type', type=click.STRING, nargs=1)
@click.argument(u'auth-id', type=click.STRING, nargs=1)
@click.argument(u'permission', type=click.STRING, nargs=1)
def update_acl(resource_id, auth_type, auth_id, permission):
    ckan_context = {
        'model': model,
        'session': model.Session,
        'ignore_auth': True
    }
    admin_user = get_action('get_site_user')(ckan_context, {})
    context = {
        'model': model,
        'session': model.Session,
        'user': admin_user['name'],
        'ignore_auth': True,
    }
    data_dict = {
        'resource_id': resource_id,
        'auth_type': auth_type,
        'auth_id': auth_id,
        'permission': permission
    }
    acl = get_action('resource_acl_update')(context, data_dict)
    print_acl(acl)


def print_acl(acl):
    print('              id: %s' % acl.get('id'))
    print('     resource id: %s' % acl.get('resource_id'))
    print('       auth type: %s' % acl.get('auth_type'))
    print('         auth id: %s' % acl.get('auth_id'))
    print('      permission: %s' % acl.get('permission'))
    print('         created: %s' % acl.get('created'))
    print('   last modified: %s' % acl.get('last_modified'))
    print(' creator user id: %s' % acl.get('creator_user_id'))
    print('modifier user id: %s' % acl.get('modifier_user_id'))
    print('')
