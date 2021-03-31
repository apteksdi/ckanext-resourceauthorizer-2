from flask import Blueprint, make_response
from flask.views import MethodView

from ckan.plugins.toolkit import (request, abort, render, c, h,
                                  _)
from ckan.logic import (ValidationError, NotAuthorized, NotFound, check_access,
                        get_action, clean_dict, tuplize_dict, parse_params)
import ckan.lib.navl.dictization_functions as dict_fns
import ckan.model as model


resourceauthorizer = Blueprint(u'resourceauthorizer', __name__)


class ResourceAuthorizerAPI(MethodView):
    def get(self, dataset_id, resource_id):
        try:
            c.pkg_dict = get_action('package_show')(None, {'id': dataset_id})
            c.resource = get_action('resource_show')(None, {'id': resource_id})
            rec = get_action('resource_acl_list')(None, {
                'resource_id': resource_id,
                'limit': 0
            })
        except NotAuthorized:
            abort(403)
        except NotFound:
            abort(404)
        return render(
            'resource-authorizer/acl.html',
            extra_vars={
                'pkg_dict': c.pkg_dict,
                'resource': c.resource,
                'acls': rec,
                'dataset_id': dataset_id,
                'resource_id': resource_id
            })

    def delete(self, dataset_id, resource_id, id):
        context = {'model': model, 'session': model.Session, 'user': c.user}
        try:
            if request.method == 'POST':
                get_action('resource_acl_delete')(context, {'id': id})
                h.flash_notice(_('Resource ACL has been deleted.'))
                h.redirect_to(
                    action='resourceauthorizer.resource_acl',
                    dataset_id=dataset_id,
                    resource_id=resource_id
                )
        except NotAuthorized:
            abort(403)
        except NotFound:
            abort(404)


class CreateResourceAuthorizerAPI(MethodView):
    def get(self, dataset_id, resource_id):
        context = {'model': model, 'session': model.Session, 'user': c.user}
        try:
            check_access('resource_acl_create', context, {
                'resource_id': resource_id
            })
        except NotAuthorized:
            abort(403, _('Unauthorized to create resource acl %s') % '')
        try:
            c.pkg_dict = get_action('package_show')(None, {'id': dataset_id})
            c.resource = get_action('resource_show')(None, {'id': resource_id})
            c.permissions = [{
                'text': u'None',
                'value': 'none'
            }, {
                'text': u'Read',
                'value': 'read'
            }]
            acl = request.params.get('id')
            if acl:
                c.acl_dict = get_action('resource_acl_show')(context, {
                    'id': acl
                })
                if c.acl_dict['auth_type'] == 'user':
                    c.auth = get_action('user_show')(
                        context, {
                            'id': c.acl_dict['auth_id']
                        })
                else:
                    c.auth = get_action('organization_show')(
                        context, {
                            'id': c.acl_dict['auth_id']
                        })
                c.acl_permission = c.acl_dict['permission']
        except NotAuthorized:
            abort(403)
        except NotFound:
            abort(404)
        except ValidationError as e:
            h.flash_error(e.error_summary)
        return render(
            'resource-authorizer/acl_new.html',
            extra_vars={
                'pkg_dict': c.pkg_dict,
                'resource': c.resource,
                'dataset_id': dataset_id,
                'resource_id': resource_id
            })

    def post(self, dataset_id, resource_id):
        context = {'model': model, 'session': model.Session, 'user': c.user}
        try:
            check_access('resource_acl_create', context, {
                'resource_id': resource_id
            })
        except NotAuthorized:
            abort(403, _('Unauthorized to create resource acl %s') % '')
        try:
            c.pkg_dict = get_action('package_show')(None, {'id': dataset_id})
            c.resource = get_action('resource_show')(None, {'id': resource_id})
            c.permissions = [{
                'text': u'None',
                'value': 'none'
            }, {
                'text': u'Read',
                'value': 'read'
            }]
            data_dict = clean_dict(
                dict_fns.unflatten(
                    tuplize_dict(parse_params(request.params))))
            acl = data_dict.get('id')
            if acl is None:
                data = {
                    'resource_id': resource_id,
                    'permission': data_dict['permission']
                }
                if data_dict['organization']:
                    group = model.Group.get(data_dict['organization'])
                    if not group:
                        message = _(u'Organization {org} does not exist.').format(
                            org=data_dict['organization'])
                        raise ValidationError(
                            {
                                'message': message
                            }, error_summary=message)
                    data['auth_type'] = 'org'
                    data['auth_id'] = group.id
                elif data_dict['username']:
                    user = model.User.get(data_dict['username'])
                    if not user:
                        message = _(u'User {username} does not exist.').format(
                            username=data_dict['username'])
                        raise ValidationError(
                            {
                                'message': message
                            }, error_summary=message)
                    data['auth_type'] = 'user'
                    data['auth_id'] = user.id
                get_action('resource_acl_create')(None, data)
            else:
                data = {'id': acl, 'permission': data_dict['permission']}
                get_action('resource_acl_patch')(None, data)
            h.redirect_to(
                action='resourceauthorizer.resource_acl',
                dataset_id=dataset_id,
                resource_id=resource_id
            )
        except NotAuthorized:
            abort(403)
        except NotFound:
            abort(404)
        except ValidationError as e:
            h.flash_error(e.error_summary)


resourceauthorizer.add_url_rule(('/dataset/<dataset_id>/'
                                 'resource/<resource_id>/'
                                 'acl'),
                                view_func=ResourceAuthorizerAPI.as_view(
                                    'resource_acl'),
                                methods=['GET'])
resourceauthorizer.add_url_rule(('/dataset/<dataset_id>/'
                                 'resource/<resource_id>/'
                                 'acl/<id>'),
                                view_func=ResourceAuthorizerAPI.as_view(
                                    'resource_acl_delete'),
                                methods=['DELETE'])
resourceauthorizer.add_url_rule(('/dataset/<dataset_id>/'
                                 'resource/<resource_id>/'
                                 'acl_new'),
                                view_func=CreateResourceAuthorizerAPI.as_view(
                                    'resource_acl_new'),
                                methods=['GET', 'POST'])

