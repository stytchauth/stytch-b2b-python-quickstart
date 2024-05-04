import os
import sys

import dotenv
import stytch
from stytch.b2b.models.organizations import SearchQuery
from stytch.b2b.models.organizations import UpdateRequestOptions
from stytch.shared.method_options import Authorization
from flask import Flask, request, url_for, session, redirect, render_template


# load the .env file
dotenv.load_dotenv()

# By default, run on localhost:3000
HOST = os.getenv("HOST", "localhost")
PORT = int(os.getenv("PORT", "3000"))

# Set ENV to "live" to hit the live API environment
ENV = os.getenv("ENV", "test")

# Load the Stytch credentials, but quit if they aren't defined
STYTCH_PROJECT_ID = os.getenv("STYTCH_PROJECT_ID")
if STYTCH_PROJECT_ID is None:
    sys.exit("STYTCH_PROJECT_ID env variable must be set before running")

STYTCH_SECRET = os.getenv("STYTCH_SECRET")
if STYTCH_SECRET is None:
    sys.exit("STYTCH_SECRET env variable must be set before running")

stytch_client = stytch.B2BClient(
    project_id=STYTCH_PROJECT_ID,
    secret=STYTCH_SECRET,
    environment=ENV
)

# create a Flask web app
app = Flask(__name__)
app.secret_key = 'some-secret-key'


@app.route('/')
def index():
    member, organization = get_authenticated_member_and_organization()
    if member and organization:
        return render_template('loggedIn.html', member=member, organization=organization)
    
    return render_template('discoveryLogin.html')

@app.route('/logout')
def logout():
    session.pop('stytch_session_token', None)
    return redirect(url_for('index'))


# Example of initiating Magic Link authentication
# Magic Links can be used for "Discovery Sign-up or Login" (no OrgID passed)
# OR "Organization Login" (with an OrgID passed)
# You can read more about these differences here: https://stytch.com/docs/b2b/guides/login-flows 
@app.route('/send_magic_link', methods=['POST'])
def send_eml():
    email = request.form.get('email', None)
    if email is None:
        return 'Email is required', 400
    
    organization_id = request.form.get('organization_id', None)
    if organization_id is None:
        resp = stytch_client.magic_links.email.discovery.send(email_address=email)
        if resp.status_code != 200:
            print(resp)
            return 'Error sending discovery magic link!', 500
        return render_template('emailSent.html')
    
    resp = stytch_client.magic_links.email.login_or_signup(email_address=email, organization_id=organization_id)
    if resp.status_code != 200:
        print(resp)
        return 'Error sending organization magic link!', 500
    return render_template('emailSent.html')


# Example of completing multi-step auth flow
# For these flows Stytch will call the Redirect URL specified in your dashboard
# with an auth token and stytch_token_type that allow you to complete the flow
# Read more about Redirect URLs and Token Types here: https://stytch.com/docs/b2b/guides/dashboard/redirect-urls
@app.route('/authenticate', methods=['GET'])
def authenticate():
    token_type = request.args['stytch_token_type']
    token = request.args['token']

    if token_type == 'discovery':
        resp = stytch_client.magic_links.discovery.authenticate(discovery_magic_links_token=token)
        if resp.status_code != 200:
            print(resp)
            return 'Error authenticating discovery magic link', 500
        
        # The intermediate_session_token (IST) allows you to persist authentication state
        # while you present the user with the Organizations they can log into, or the option to create a new Organization
        session['ist'] = resp.intermediate_session_token
        orgs = []
        for discovered in resp.discovered_organizations:
            org = {
                'organization_id': discovered.organization.organization_id,
                'organization_name': discovered.organization.organization_name,
            }
            orgs.append(org)

        return render_template(
            'discoveredOrganizations.html',
            discovered_organizations=orgs,
            email_address=resp.email_address,
            is_login=True
        )

    elif token_type == 'multi_tenant_magic_links':
        resp = stytch_client.magic_links.authenticate(magic_links_token=token)
        if resp.status_code != 200:
            print(resp)
            return 'Error authenticating organization magic link', 500
        
        session['stytch_session_token'] = resp.session_token
        return redirect(url_for('index'))
    else:
        return 'Unsupported auth method', 500

# Example of creating a new Organization after Discovery authentication
# To test, select "Create New Organization" and input a name and slug for your new org
# This will then exchange the IST returned from the discovery.authenticate() call
# which allows Stytch to enforce that users are properly authenticated and verified
# prior to creating an Organization
@app.route('/create_organization', methods=['POST'])
def create_organization():
    ist = session.get('ist')
    if not ist:
        return 'IST required to create an Organization', 400
    
    org_name = request.form.get('org_name', '')
    org_slug = request.form.get('org_slug', '')
    clean_org_slug = org_slug.replace(' ', '-')

    resp = stytch_client.discovery.organizations.create(
        intermediate_session_token=ist,
        organization_name=org_name,
        organization_slug=clean_org_slug,
    )
    if resp.status_code != 200:
        return "Error creating org"

    session.pop('ist', None)
    session['stytch_session_token'] = resp.session_token
    return redirect(url_for('index'))

# After Discovery, users can opt to log into an existing Organization
# that they belong to or are eligible to join by Email Domain JIT Provision or a pending invite
# You will exchange the IST returned from the discovery.authenticate() method call
# to complete the login process
@app.route('/exchange/<string:organization_id>')
def exchange_into_organization(organization_id):
    ist = session.get('ist', None)
    if ist:
        resp = stytch_client.discovery.intermediate_sessions.exchange(
            intermediate_session_token=ist,
            organization_id=organization_id
        )
        if resp.status_code != 200:
            print(resp)
            return 'Error exchanging IST into Organization', 500
        
        session.pop('ist', None)
        session['stytch_session_token'] = resp.session_token
        return redirect(url_for('index'))
    
    session_token = session.get('stytch_session_token')
    if not session_token:
        return 'Either IST or Session Token required', 400
    
    resp = stytch_client.sessions.exchange(
        organization_id=organization_id,
        session_token=session_token
    )
    if resp.status_code != 200:
        return 'Error exchanging Session Token into Organization', 500
    session['stytch_session_token'] = resp.session_token
    return redirect(url_for('index'))


# Example of Organization Switching post-authentication
# This allows a logged in Member on one Organization to "exchange" their
# session for a session on another Organization that they belong to
# all while ensuring that each Organization's authentication requirements are honored
# and respecting data isolation between tenants
@app.route('/switch_orgs')
def switch_orgs():
    session_token = session.get('stytch_session_token', None)
    if session_token is None:
        return redirect(url_for('index'))

    resp = stytch_client.discovery.organizations.list(session_token=session.get('stytch_session_token', None))
    if resp.status_code != 200:
        print(resp)
        return 'Error listing discovered organizations', 500
    
    discovered_orgs = resp.discovered_organizations
    orgs = []
    for discovered_org in discovered_orgs:
        orgs.append({'organization_id': discovered_org.organization.organization_id, 'organization_name': discovered_org.organization.organization_name})
    
    return render_template(
        'discoveredOrganizations.html',
        discovered_organizations=orgs,
        email_address=resp.email_address,
        is_login=False
    )

# Example of Organization Login (if logged out)
# Example of Session Exchange (if logged in)
@app.route('/orgs/<string:organization_slug>')
def organization_index(organization_slug):
    member, organization = get_authenticated_member_and_organization()
    if member and organization:
        if organization_slug == organization.organization_slug:
            # User is currently logged into this Organization
            return redirect(url_for('index'))

        # Check to see if User currently belongs to Organization
        resp = stytch_client.discovery.organizations.list(session_token=session.get('stytch_session_token', None))
        if resp.status_code != 200:
            print(resp)
            return 'Error listing discovered organizations', 500
        
        discovered_orgs = resp.discovered_organizations
        for discovered_org in discovered_orgs:
            if discovered_org.organization.organization_slug == organization_slug:
                return redirect(url_for('exchange_into_organization', organization_id=discovered_org.organization.organization_id))
    
    # User isn't a current member of Organization, have them login
    resp = stytch_client.organizations.search(query=SearchQuery(operator='AND', operands=[{
        'filter_name': 'organization_slugs',
        'filter_value': [organization_slug]}
    ]))
    if resp.status_code != 200 or len(resp.organizations) == 0:
        return 'Error fetching org by slug', 500

    organization = resp.organizations[0]
    return render_template(
        'organizationLogin.html',
        organization_id=organization.organization_id,
        organization_name=organization.organization_name
    )

# Example of authorized updating of Organization Settings + Just-in-Time (JIT) Provisioning
# Once enabled:
# 1. Logout
# 2. Initiate magic link for an email alias (e.g. ada+1@stytch.com)
# 3. After clicking the Magic Link you'll see the option to join the organization with JIT enabled
# Use your work email address to test this, as JIT cannot be enabled for common email domains
@app.route('/enable_jit')
def enable_jit():
    member, organization = get_authenticated_member_and_organization()
    if member is None or organization is None:
        return redirect(url_for('index'))
    
    # Note: not allowed for common domains like gmail.com
    domain = member.email_address.split('@')[1]

    # When the session_token or session_jwt are passed into method_options
    # Stytch will do AuthZ enforcement based on the Session Member's RBAC permissions
    # before honoring the request
    resp = stytch_client.organizations.update(
        organization_id=organization.organization_id,
        email_jit_provisioning='RESTRICTED',
        email_allowed_domains=[domain],
        method_options=UpdateRequestOptions(
            authorization=Authorization(
                session_token=session.get('stytch_session_token', None),
            ),
        ),
    )
    if resp.status_code != 200:
        print(resp)
        return 'Error updating Organization JIT Provisioning settings'
    
    return redirect(url_for('index'))

# Helper to retrieve the authenticated Member and Organization context
def get_authenticated_member_and_organization():
    stytch_session = session.get('stytch_session_token')
    if not stytch_session:
        return None, None

    resp = stytch_client.sessions.authenticate(session_token=stytch_session)
    print(resp)
    if resp.status_code != 200:
        print('Invalid session')
        session.pop('stytch_session_token')
        return None, None

    # Remember to reset the cookie session, as sessions.authenticate() will issue a new token
    session['stytch_session_token'] = resp.session_token
    return resp.member, resp.organization

# run's the app on the provided host & port
if __name__ == "__main__":
    # in production you would want to make sure to disable debugging
    app.run(host=HOST, port=PORT, debug=True)