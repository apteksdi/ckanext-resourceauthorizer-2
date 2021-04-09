from flask import Blueprint, make_response
from flask.views import MethodView

from ckan.plugins.toolkit import (request, abort, render, c, h,
                                  _)
from ckan.logic import (ValidationError, NotAuthorized, NotFound, check_access,
                        get_action, clean_dict, tuplize_dict, parse_params)
import ckan.lib.navl.dictization_functions as dict_fns
import ckan.model as model
import pprint
pp = pprint.PrettyPrinter(width=41, compact=True)


resourceauthorizer = Blueprint(u'resourceauthorizer', __name__)


class MainPageAPI(MethodView):
    def get(self, dataset_id, resource_id):
        try:
            pkg_dict = get_action('package_show')(None, {'id': dataset_id})
            resource = get_action('resource_show')(None, {'id': resource_id})
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
                'pkg_dict': pkg_dict,
                'resource': resource,
                'acls': rec,
                'dataset_id': dataset_id,
                'resource_id': resource_id
            })

class DeleteAPI(MethodView):
    """Method here is supposed to be 'delete' but due to limitations of the
    structure CKAN puts in place for extensions, this hack must be used. We
    do this because API is invoked by clikcing on an 'a href' link instead of
    being invoked by Javascript."""
    def post(self, dataset_id, resource_id, id):
        context = {'model': model, 'session': model.Session, 'user': c.user}
        try:
            get_action('resource_acl_delete')(context, {'id': id})
            h.flash_notice(_('Resource ACL has been deleted.'))
            return h.redirect_to(
                'resourceauthorizer.resource_acl',
                dataset_id=dataset_id,
                resource_id=resource_id
            )
        except NotAuthorized:
            abort(403)
        except NotFound:
            abort(404)


class ModifyPageAPI(MethodView):
    def get(self, dataset_id, resource_id):
        context = {'model': model, 'session': model.Session, 'user': c.user}
        pkg_dict = None
        resource = None
        permissions = None
        acl = None
        acl_dict=None
        acl_permission = None
        try:
            check_access('resource_acl_create', context, {
                'resource_id': resource_id
            })
        except NotAuthorized:
            abort(403, _('Unauthorized to create resource acl %s') % '')
        try:
            pkg_dict = get_action('package_show')(None, {'id': dataset_id})
            resource = get_action('resource_show')(None, {'id': resource_id})
            permissions = [{
                'text': u'None',
                'value': 'none'
            }, {
                'text': u'Read',
                'value': 'read'
            }]
            acl = request.params.get('id')
            if acl:
                acl_dict = get_action('resource_acl_show')(context, {
                    'id': acl
                })
                if acl_dict['auth_type'] == 'user':
                    auth = get_action('user_show')(
                        context, {
                            'id': acl_dict['auth_id']
                        })
                else:
                    auth = get_action('organization_show')(
                        context, {
                            'id': acl_dict['auth_id']
                        })
                acl_permission = acl_dict['permission']
        except NotAuthorized:
            abort(403)
        except NotFound:
            abort(404)
        except ValidationError as e:
            h.flash_error(e.error_summary)
        return render(
            'resource-authorizer-detail/acl_detail.html',
            extra_vars={
                'pkg_dict': pkg_dict,
                'resource': resource,
                'dataset_id': dataset_id,
                'resource_id': resource_id,
                'acl_dict': acl_dict,
                'acl_permission': acl_permission,
                'permissions': permissions
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
            pkg_dict = get_action('package_show')(None, {'id': dataset_id})
            resource = get_action('resource_show')(None, {'id': resource_id})
            permissions = [{
                'text': u'None',
                'value': 'none'
            }, {
                'text': u'Read',
                'value': 'read'
            }]
            data_dict = clean_dict(
                dict_fns.unflatten( 
                    tuplize_dict(parse_params(request.form))))
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
            return h.redirect_to(
                'resourceauthorizer.resource_acl',
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
                                view_func=MainPageAPI.as_view(
                                    'resource_acl'),
                                methods=['GET'])
resourceauthorizer.add_url_rule(('/dataset/<dataset_id>/'
                                 'resource/<resource_id>/'
                                 'acl/<id>/delete'),
                                view_func=DeleteAPI.as_view(
                                    'resource_acl_delete'),
                                methods=['POST'])
resourceauthorizer.add_url_rule(('/dataset/<dataset_id>/'
                                 'resource/<resource_id>/'
                                 'acl_new'),
                                view_func=ModifyPageAPI.as_view(
                                    'resource_acl_new'),
                                methods=['GET', 'POST'])

