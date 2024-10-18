import os
import sys

import logging
import dotenv
import stytch
from stytch.b2b.models.organizations import SearchQuery
from stytch.b2b.models.organizations import UpdateRequestOptions
from stytch.shared.method_options import Authorization
from stytch.core.response_base import StytchError
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

STYTCH_PUBLIC_TOKEN = os.getenv("STYTCH_PUBLIC_TOKEN")
if STYTCH_PUBLIC_TOKEN is None:
    sys.exit("STYTCH_PUBLIC_TOKEN env variable must be set before running")

stytch_client = stytch.B2BClient(
    project_id=STYTCH_PROJECT_ID,
    secret=STYTCH_SECRET,
    environment=ENV
)

# create a Flask web app
app = Flask(__name__)
app.secret_key = 'some-secret-key'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route('/')
def index():
    member, organization = get_authenticated_member_and_organization()
    if member and organization:
        return render_template('loggedIn.html', member=member, organization=organization)
    
    return render_template('discoveryLogin.html', public_token=STYTCH_PUBLIC_TOKEN)

@app.route('/logout')
def logout():
    session.pop('stytch_session_token', None)
    return redirect(url_for('index'))


# Example of initiating a magic link for sign-up or login from
# a centralized login page (no organizationID specified)
@app.route('/send_magic_link', methods=['POST'])
def send_eml():
    email = request.form.get('email', None)
    if email is None:
        logger.error("Email is required")
        return redirect(url_for("oops"))
    
    try:
        stytch_client.magic_links.email.discovery.send(email_address=email)
    except StytchError as e:
        logger.error(f"Error sending an organization login or sign-up magic link: {e.details}")
        return redirect(url_for("oops"))
            
    return render_template('emailSent.html')


# Sign-up and Login Redirect URL specified in the Stytch dashboard 
# https://stytch.com/docs/b2b/guides/dashboard/redirect-urls
# Securely receives a token from Stytch and exchanges it for an intermediate session token
# and information about which organizations the authenticated user can opt to log into
@app.route('/authenticate', methods=['GET'])
def authenticate():
    token_type = request.args['stytch_token_type']
    token = request.args['token']

    if token_type == 'discovery':
        try:
            resp = stytch_client.magic_links.discovery.authenticate(discovery_magic_links_token=token)
        except StytchError as e:
            logger.error(f"Error authenticating discovery magic link token: {e.details}")
            return redirect(url_for("oops"))
    elif token_type == 'discovery_oauth':
        try:
            resp = stytch_client.oauth.discovery.authenticate(discovery_oauth_token=token)
        except StytchError as e:
            logger.error(f"Error authenticating discovery oauth token: {e.details}")
            return redirect(url_for("oops"))
    else:
        logger.error("Unsupported token type for this example")
        return redirect(url_for("oops"))
    
    # The intermediate_session_token (IST) allows you to persist authentication state
    # while you present the user with the Organizations they can log into, or the option to create a new Organization
    session['ist'] = resp.intermediate_session_token
    orgs = format_discovered_organizations(resp.discovered_organizations)

    return render_template(
        'discoveredOrganizations.html',
        discovered_organizations=orgs,
        email_address=resp.email_address,
        is_login=True
    )

# Example of creating a new Organization after Discovery authentication
# To test, select "Create New Organization" and input a name and slug for your new org
# This will then exchange the IST returned from the discovery.authenticate() call
# which allows Stytch to enforce that users are properly authenticated and verified
# prior to creating an Organization
@app.route('/create_organization', methods=['POST'])
def create_organization():
    ist = session.get('ist', None)
    if ist is None:
        logger.error("IST required to create an Organization")
        return redirect(url_for("oops"))
    
    org_name = request.form.get('org_name', '')
    org_slug = request.form.get('org_slug', '')
    clean_org_slug = org_slug.replace(' ', '-')

    try:
        resp = stytch_client.discovery.organizations.create(
            intermediate_session_token=ist,
            organization_name=org_name,
            organization_slug=clean_org_slug,
        )
    except StytchError as e:
        logger.error(f"Error creating a new organization: {e.details}")
        return redirect(url_for("oops"))

    session.pop('ist', None)
    session['stytch_session_token'] = resp.session_token
    return redirect(url_for('index'))

# Handles logging an end user into a specific Organization in two circumstances:
# (1) selecting the org they wish to log into during discovery sign-up or login
# (2) switching into another organization they belong to under the same email
@app.route('/exchange/<string:organization_id>')
def exchange_into_organization(organization_id):
    
    # During the discovery flow, you will exchange the IST returned from the
    # discovery.authenticate() call for a Member Session on the Organization the
    # user selects
    ist = session.get('ist', None)
    if ist:
        try:
            resp = stytch_client.discovery.intermediate_sessions.exchange(
                intermediate_session_token=ist,
                organization_id=organization_id
            )
        except StytchError as e:
            logger.error(f"Error exchange IST into organization: {e.details}")
            return redirect(url_for("oops"))
        
        session.pop('ist', None)
        session['stytch_session_token'] = resp.session_token
        return redirect(url_for('index'))
    
    # When a user is logged in, they can "exchange" their current Member Session
    # on one Organization for a Member Session on another Organization they belong to
    # under the same email
    session_token = session.get('stytch_session_token', None)
    if session_token is None:
        logger.error(f"Either IST or Session Token required")
        return redirect(url_for("oops"))
    
    try:
        resp = stytch_client.sessions.exchange(
            organization_id=organization_id,
            session_token=session_token
        )
    except StytchError as e:
        logger.error(f"Error exchange session token into organization for org switching: {e.details}")
        return redirect(url_for("oops"))

    session['stytch_session_token'] = resp.session_token
    return redirect(url_for('index'))


# Fetches organizations that the currently authenticated end user can "switch" into
# seamlessly exchanging their session on one organization for a session on another
# that they belong to under the same email
@app.route('/orgs-for-switching')
def orgs_for_switching():
    session_token = session.get('stytch_session_token', None)
    if session_token is None:
        return redirect(url_for('index'))

    try:
        resp = stytch_client.discovery.organizations.list(session_token=session.get('stytch_session_token', None))
    except StytchError as e:
        logger.error(f"Error listing discovered organizations for org switching: {e.details}")
        return redirect(url_for("oops"))
    
    orgs = format_discovered_organizations(resp.discovered_organizations)
    
    return render_template(
        'discoveredOrganizations.html',
        discovered_organizations=orgs,
        email_address=resp.email_address,
        is_login=False
    )

# Example of RBAC-authorized updating of Organization Settings to enable
# Just-in-Time (JIT) Provisioning by email domain
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
    try:
        stytch_client.organizations.update(
            organization_id=organization.organization_id,
            email_jit_provisioning='RESTRICTED',
            email_allowed_domains=[domain],
            method_options=UpdateRequestOptions(
                authorization=Authorization(
                    session_token=session.get('stytch_session_token', None),
                ),
            ),
        )
    except StytchError as e:
        logger.error(f"Error updating the organization's JIT provisioning settings: {e.details}")
        return redirect(url_for("oops"))
    
    return redirect(url_for('index'))

@app.route("/oops")
def oops():
    return render_template("oops.html")

# Helper to retrieve the authenticated Member and Organization context
def get_authenticated_member_and_organization():
    stytch_session = session.get('stytch_session_token')
    if not stytch_session:
        return None, None

    try:
        resp = stytch_client.sessions.authenticate(session_token=stytch_session)
    except StytchError as e:
        if e.details.error_type == "session_not_found":
            # Session has expired or is invalid, clear it
            logger.info("Session expired or has been revoked")
        else:
            logger.error(f"Error authenticating session: {e.details}")
        session.pop("stytch_session_token", None)
        return None, None

    # Remember to reset the cookie session, as sessions.authenticate() will issue a new token
    session['stytch_session_token'] = resp.session_token
    return resp.member, resp.organization

def format_discovered_organizations(discovered_orgs):
    orgs = []
    for discovered in discovered_orgs:
        formatted = {
            'organization_id': discovered.organization.organization_id,
            'organization_name': discovered.organization.organization_name,
            'membership_type': discovered.membership.type
        }
        orgs.append(formatted)
    return orgs

# run's the app on the provided host & port
if __name__ == "__main__":
    # in production you would want to make sure to disable debugging
    app.run(host=HOST, port=PORT, debug=True)