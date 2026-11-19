"""Plain-English rotation plans, one per provider.

This is the part that makes the scanner useful: a leaked key is only half the
story. The report has to say where to revoke it, what to replace it with, and
how to prove the old one is dead.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RotationPlan:
    title: str
    access: str
    revoke_url: str
    steps: list[str]
    verify: str
    cleanup: list[str]


PLANS: dict[str, RotationPlan] = {
    "aws": RotationPlan(
        title="AWS access key",
        access="Anyone who saw the file, repo, zip, screenshot, or CI log can use "
        "this key until it is deactivated.",
        revoke_url="https://console.aws.amazon.com/iam/home#/security_credentials",
        steps=[
            "Sign in to AWS, open IAM, then Users, then the affected user.",
            "Open Security credentials and deactivate the exposed access key.",
            "Create a replacement key and store it in a secret manager or CI secret.",
            "Update the app or script that used the old key, then deploy.",
            "Check CloudTrail for unusual calls between the leak and now.",
        ],
        verify="Run `aws sts get-caller-identity` with the new key. The old key "
        "must return InvalidClientTokenId.",
        cleanup=[
            "Delete the key from the file and from every copy you made.",
            "Purge it from git history with git filter-repo or BFG, then force-push.",
            "Check the AWS bill for resources you did not create.",
        ],
    ),
    "github": RotationPlan(
        title="GitHub token",
        access="The token can act as your account or app wherever its scopes "
        "reach, including private repositories and organization settings.",
        revoke_url="https://github.com/settings/tokens",
        steps=[
            "Open GitHub Settings, then Developer settings, then Personal access "
            "tokens, and revoke the exposed token.",
            "Create a replacement with the smallest scopes that still work.",
            "Update CI secrets, .env files, and any local scripts.",
            "Review the account security log for token use you do not recognise.",
        ],
        verify="Call `https://api.github.com/user` with the new token. The old "
        "token must return 401 Bad credentials.",
        cleanup=[
            "Remove the token from the file, README, and commit history.",
            "Rotate any deploy key or secret the token could read.",
        ],
    ),
    "slack": RotationPlan(
        title="Slack token",
        access="A bot or user token can read channel history and post as the app "
        "or person until it is revoked.",
        revoke_url="https://api.slack.com/apps",
        steps=[
            "Open your Slack app, then OAuth & Permissions, and reinstall or "
            "rotate the token.",
            "For a user token, revoke the session under the account's security "
            "settings.",
            "Update the integration with the new token and restart it.",
            "Check the app's activity log for messages you did not send.",
        ],
        verify="Call Slack `auth.test` with the new token. The old token must "
        "return invalid_auth.",
        cleanup=[
            "Delete the token from messages, docs, and code.",
            "Remove any webhook or bot the old token created.",
        ],
    ),
    "google": RotationPlan(
        title="Google API key",
        access="The key can call enabled APIs and bill your project, especially "
        "if it has no application restrictions.",
        revoke_url="https://console.cloud.google.com/apis/credentials",
        steps=[
            "Open Google Cloud Console, then APIs & Services, then Credentials.",
            "Delete the exposed key.",
            "Create a replacement and add API, referrer, or IP restrictions.",
            "Update the app and deploy.",
            "Check the project's usage and billing for unexpected calls.",
        ],
        verify="Call an enabled API with the new key. The old key must return "
        "403 or 400 API key not valid.",
        cleanup=[
            "Remove the key from public code and screenshots.",
            "Set a budget alert so future abuse is visible.",
        ],
    ),
    "stripe": RotationPlan(
        title="Stripe live secret key",
        access="A live key can move real money: charges, refunds, customer data, "
        "and payout details.",
        revoke_url="https://dashboard.stripe.com/apikeys",
        steps=[
            "Open the Stripe Dashboard, then Developers, then API keys.",
            "Roll the exposed live key immediately.",
            "Update the server environment and redeploy.",
            "Review payments, refunds, and logs for activity you did not make.",
        ],
        verify="Run `stripe balance retrieve` with the new key. The old key must "
        "return 401.",
        cleanup=[
            "Remove the key from code, notebooks, and chat.",
            "Contact Stripe Support if you see unauthorised charges.",
        ],
    ),
    "openai": RotationPlan(
        title="OpenAI API key",
        access="Anyone with the key can spend your balance and, depending on the "
        "account, reach fine-tunes and files.",
        revoke_url="https://platform.openai.com/api-keys",
        steps=[
            "Open the OpenAI dashboard, then API keys, and revoke the key.",
            "Create a replacement and set a monthly spend limit.",
            "Update the app or automation and redeploy.",
            "Check usage for requests you did not make.",
        ],
        verify="Call `GET https://api.openai.com/v1/models` with the new key. The "
        "old key must return 401.",
        cleanup=["Remove the key from code and logs.", "Lower the spend limit."],
    ),
    "anthropic": RotationPlan(
        title="Anthropic API key",
        access="Anyone with the key can spend your balance and use your account's "
        "rate limits.",
        revoke_url="https://console.anthropic.com/settings/keys",
        steps=[
            "Open the Anthropic Console, then API keys, and revoke the key.",
            "Create a replacement and set a spend limit.",
            "Update the app and redeploy.",
            "Check usage for requests you did not make.",
        ],
        verify="Call the Messages API with the new key. The old key must return 401.",
        cleanup=["Remove the key from code, notes, and logs."],
    ),
    "sendgrid": RotationPlan(
        title="SendGrid API key",
        access="The key can send email as your verified domains, which can damage "
        "your sender reputation.",
        revoke_url="https://app.sendgrid.com/settings/api_keys",
        steps=[
            "Open SendGrid, then Settings, then API Keys, and delete the key.",
            "Create a replacement with only the permissions you need.",
            "Update the sending service and redeploy.",
            "Review the activity feed for mail you did not send.",
        ],
        verify="Send one test email with the new key. The old key must return 401.",
        cleanup=["Remove the key from code and shared notes."],
    ),
    "twilio": RotationPlan(
        title="Twilio API key",
        access="The key can send SMS or calls and charge your account.",
        revoke_url="https://console.twilio.com/us1/account/keys",
        steps=[
            "Open Twilio Console, then Account, then API keys and tokens.",
            "Delete the exposed key.",
            "Create a replacement and update the app.",
            "Check the message and call logs for activity you did not make.",
        ],
        verify="Send one test message with the new key. The old key must fail.",
        cleanup=["Remove the key from code and chat."],
    ),
    "private_key": RotationPlan(
        title="Private key",
        access="This key can impersonate a server, a user, or a signing identity. "
        "Treat every system that trusts it as affected.",
        revoke_url="",
        steps=[
            "Identify what the key protects: SSH login, TLS, code signing, or a VPN.",
            "Generate a new key pair on the machine that needs it.",
            "Install the new public key or certificate on the server or service.",
            "Remove the old public key from authorized_keys, keystores, and trusts.",
            "Restart the affected service and test.",
        ],
        verify="Connect or sign with the new key. The old private key must be "
        "rejected.",
        cleanup=[
            "Delete the key from the repo and every backup.",
            "Purge it from git history and reissue any certificate that used it.",
        ],
    ),
    "url_credentials": RotationPlan(
        title="Password inside a URL",
        access="Anyone who saw the link can sign in as that user without any "
        "second step.",
        revoke_url="",
        steps=[
            "Sign in to that service and change the password immediately.",
            "If the password is reused anywhere else, change it there too.",
            "Replace the link with a token or a secret manager lookup.",
            "Check the account's login history for unknown sessions.",
        ],
        verify="Try the old link. It must fail to sign in.",
        cleanup=["Remove the link from code, docs, and chat history."],
    ),
    "jwt": RotationPlan(
        title="JSON Web Token",
        access="The token stays valid until it expires, even if the password "
        "changes. It may carry admin claims.",
        revoke_url="",
        steps=[
            "Identify the service that issued the token.",
            "Revoke the session or refresh token for that user.",
            "Rotate the signing secret so every token from the old key dies.",
            "Shorten the token lifetime and add a revocation check.",
        ],
        verify="Call a protected endpoint with the old token. It must return 401.",
        cleanup=["Remove the token from logs and browser storage captures."],
    ),
    "discord": RotationPlan(
        title="Discord webhook",
        access="Anyone with the URL can post into the channel. Deleting a message "
        "does not revoke the webhook.",
        revoke_url="https://support.discord.com/hc/en-us/articles/228383668",
        steps=[
            "Open the channel, then Edit Channel, then Integrations, then Webhooks.",
            "Delete the exposed webhook.",
            "Create a replacement only if you still need one.",
            "Check the channel for messages you did not send.",
        ],
        verify="Post to the old webhook URL. It must return 404 Unknown Webhook.",
        cleanup=["Remove the URL from code and public notes."],
    ),
    "generic": RotationPlan(
        title="Unclassified secret",
        access="The value may be a real credential. Assume anyone who saw the "
        "file can use it until the provider confirms otherwise.",
        revoke_url="",
        steps=[
            "Use the variable name and nearby code to identify the service.",
            "Sign in to that service and revoke or rotate the credential.",
            "Update every app and script that used the old value.",
            "Check the service's audit log for unknown activity.",
        ],
        verify="Test the old value against the service. It must fail.",
        cleanup=["Remove it from code and rotate anything it could unlock."],
    ),
}


def plan_for(provider: str) -> RotationPlan:
    return PLANS.get(provider, PLANS["generic"])
