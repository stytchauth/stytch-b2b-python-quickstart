# Stytch B2B Quickstart with Python Flask
Quickstart example app covering the basics for getting up and running with B2B authentication:
* Email Magic Links
* Sessions
* RBAC

## Get Started
Ensure you have pip, python and virtualenv installed

#### 1. Clone the repository.
```
git clone https://github.com/stytchauth/stytch-b2b-flask-magic-links.git
cd stytch-b2b-flask-magic-links
```

#### 2. Setup a virtualenv

We suggest creating a [virtualenv](https://docs.python.org/3/library/venv.html) and activating it to avoid installing dependencies globally
```
virtualenv -p python3 venv
source venv/bin/activate
```

#### 3. Install dependencies:
```
pip install -r requirements.txt
```

#### 4. Set ENV vars

Copy `.env.template` to `.env` and update the values with your Stytch project ID, secret and public token from [the API Keys section of the Stytch Dashboard](https://stytch.com/dashboard/api-keys).

#### 7. Run the Server
Run
```
python3 main.py
```
Go to http://localhost:3000/

## Next steps

This example app showcases a small portion of what you can accomplish with Stytch. Next, explore adding additional login methods, such as [OAuth](https://stytch.com/docs/b2b/guides/oauth/initial-setup) or [SSO](https://stytch.com/docs/b2b/guides/sso/initial-setup).

## Get help and join the community

#### :speech_balloon: Stytch community Slack

Join the discussion, ask questions, and suggest new features in our ​[Slack community](https://stytch.com/docs/resources/support/overview)!

#### :question: Need support?

Check out the [Stytch Forum](https://forum.stytch.com/) or email us at [support@stytch.com](mailto:support@stytch.com).
