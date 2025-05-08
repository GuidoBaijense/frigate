"""WebAuthn APIs for Frigate.

Implementation using the Python WebAuthn library for server-side validation.
"""

import base64
import logging
import secrets
import time
from typing import Any, Optional

# Import WebAuthn package
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from peewee import DoesNotExist
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from frigate.api.auth import (
    create_encoded_jwt,
    get_current_user,
    require_role,
    set_jwt_cookie,
)
from frigate.models import User

logger = logging.getLogger(__name__)

# Relying party settings for WebAuthn
RP_NAME = "Frigate"
RP_ICON = None  # Optional icon URL

router = APIRouter()


class WebAuthnRegistrationResponse(BaseModel):
    id: str
    rawId: str
    response: dict[str, Any]
    type: str
    clientExtensionResults: Optional[dict] = {}
    authenticatorAttachment: Optional[str] = None
    transports: Optional[list[str]] = None


class WebAuthnAuthenticationResponse(BaseModel):
    id: str
    rawId: str
    response: dict[str, Any]
    type: str
    clientExtensionResults: Optional[dict] = {}
    authenticatorAttachment: Optional[str] = None


def get_rp_id_from_request(request: Request) -> str:
    """Extract the RP ID from the request host."""
    host = request.headers.get("host", "localhost").split(":")[0]
    # Use the host without port as the RP ID
    return host


def get_origin_from_request(request: Request) -> str:
    """Extract the origin from the request."""
    host = request.headers.get("host", "localhost")
    protocol = (
        "https" if request.headers.get("x-forwarded-proto") == "https" else "http"
    )
    return f"{protocol}://{host}"


def generate_challenge() -> bytes:
    """Generate a random challenge for WebAuthn."""
    return secrets.token_bytes(32)


@router.get("/webauthn/registration-options")
async def get_registration_options(request: Request):
    """Get WebAuthn registration options for the current user."""
    current_user = await get_current_user(request)
    if isinstance(current_user, JSONResponse):
        raise HTTPException(status_code=401, detail="Unauthorized")

    username = current_user.get("username")

    try:
        user = User.get_by_id(username)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate a unique WebAuthn ID if the user doesn't have one
    if not user.webauthn_id:
        # Generate a random GUID as bytes
        webauthn_id_bytes = secrets.token_bytes(32)
        encoded_id = bytes_to_base64url(webauthn_id_bytes)
        User.set_by_id(username, {"webauthn_id": encoded_id})
        user = User.get_by_id(username)  # Refresh user data
    else:
        # Convert stored base64 ID back to bytes for the WebAuthn API
        webauthn_id_bytes = base64url_to_bytes(user.webauthn_id)

    rp_id = get_rp_id_from_request(request)
    rp_origin = get_origin_from_request(request)

    # Get existing credentials to exclude
    exclude_credentials = []
    if user.webauthn_credentials:
        for cred in user.webauthn_credentials:
            exclude_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred["id"]),
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    transports=cred.get("transports", ["internal"]),
                )
            )

    # Generate a random challenge
    challenge = generate_challenge()

    # Generate registration options
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=webauthn_id_bytes,  # This must be bytes
        user_name=username,
        user_display_name=username,
        challenge=challenge,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=None,  # Allow any authenticator
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
    )

    # Store information in the session for later verification
    # Store challenge as base64 for session compatibility
    request.session["webauthn_challenge"] = bytes_to_base64url(challenge)
    request.session["webauthn_username"] = username
    request.session["webauthn_rp_id"] = rp_id
    request.session["webauthn_origin"] = rp_origin

    # Convert to dict for JSON response
    return options.dict()


@router.get(
    "/webauthn/registration-options/{username}",
    dependencies=[Depends(require_role(["admin"]))],
)
async def get_registration_options_for_user(request: Request, username: str):
    """Get WebAuthn registration options for a specific user (admin only)."""
    try:
        user = User.get_by_id(username)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate a unique WebAuthn ID if the user doesn't have one
    if not user.webauthn_id:
        webauthn_id_bytes = secrets.token_bytes(32)
        encoded_id = bytes_to_base64url(webauthn_id_bytes)
        User.set_by_id(username, {"webauthn_id": encoded_id})
        user = User.get_by_id(username)  # Refresh user data
    else:
        # Convert stored base64 ID back to bytes for the WebAuthn API
        webauthn_id_bytes = base64url_to_bytes(user.webauthn_id)

    rp_id = get_rp_id_from_request(request)
    rp_origin = get_origin_from_request(request)

    # Get existing credentials to exclude
    exclude_credentials = []
    if user.webauthn_credentials:
        for cred in user.webauthn_credentials:
            exclude_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred["id"]),
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    transports=cred.get("transports", ["internal"]),
                )
            )

    # Generate a random challenge
    challenge = generate_challenge()

    # Generate registration options
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=webauthn_id_bytes,  # This must be bytes
        user_name=username,
        user_display_name=username,
        challenge=challenge,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=None,  # Allow any authenticator
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
    )

    # Store information in the session for later verification
    # Store challenge as base64 for session compatibility
    request.session["webauthn_challenge"] = bytes_to_base64url(challenge)
    request.session["webauthn_username"] = username
    request.session["webauthn_rp_id"] = rp_id
    request.session["webauthn_origin"] = rp_origin
    # Mark this as an admin registration
    request.session["webauthn_admin_registration"] = True

    # Convert to dict for JSON response
    return options.dict()


@router.post("/webauthn/register")
async def register_credential(
    request: Request, credential_json: WebAuthnRegistrationResponse
):
    """Register a WebAuthn credential for the current user."""
    # Get saved data from session
    username = request.session.get("webauthn_username")
    challenge_b64 = request.session.get("webauthn_challenge")
    expected_rp_id = request.session.get("webauthn_rp_id")
    expected_origin = request.session.get("webauthn_origin")

    if not username or not challenge_b64 or not expected_rp_id or not expected_origin:
        raise HTTPException(status_code=400, detail="Missing session data")

    # Convert the base64 challenge back to bytes
    challenge = base64url_to_bytes(challenge_b64)

    try:
        user = User.get_by_id(username)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    # Convert credential from pydantic model to WebAuthn format
    credential = RegistrationCredential(
        id=credential_json.id,
        raw_id=credential_json.rawId,
        response=credential_json.response,
        type=credential_json.type,
    )

    try:
        # Verify the registration response
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            require_user_verification=False,
        )
    except Exception as e:
        logger.error(f"Registration verification failed: {e}")
        raise HTTPException(status_code=400, detail=f"Verification failed: {str(e)}")

    # Get the current credentials list or initialize an empty one
    credentials = user.webauthn_credentials or []

    # Store the new credential
    new_credential = {
        "id": credential_json.id,
        "publicKey": base64.b64encode(verification.credential_public_key).decode(),
        "aaguid": verification.aaguid,
        "sign_count": verification.sign_count,
        "transports": credential_json.transports or ["internal"],
        "created_at": str(int(time.time())),
    }

    credentials.append(new_credential)
    User.set_by_id(username, {"webauthn_credentials": credentials})

    # Clear the session data
    if "webauthn_challenge" in request.session:
        del request.session["webauthn_challenge"]
    if "webauthn_username" in request.session:
        del request.session["webauthn_username"]
    if "webauthn_rp_id" in request.session:
        del request.session["webauthn_rp_id"]
    if "webauthn_origin" in request.session:
        del request.session["webauthn_origin"]

    return {"message": "Registration successful"}


@router.post(
    "/webauthn/register/{username}", dependencies=[Depends(require_role(["admin"]))]
)
async def register_credential_for_user(
    request: Request, username: str, credential_json: WebAuthnRegistrationResponse
):
    """Register a WebAuthn credential for a specific user (admin only)."""
    # Get saved data from session
    challenge_b64 = request.session.get("webauthn_challenge")
    session_username = request.session.get("webauthn_username")
    expected_rp_id = request.session.get("webauthn_rp_id")
    expected_origin = request.session.get("webauthn_origin")
    admin_registration = request.session.get("webauthn_admin_registration")

    if not challenge_b64 or not session_username or not admin_registration:
        raise HTTPException(status_code=400, detail="Missing session data")

    # Convert the base64 challenge back to bytes
    challenge = base64url_to_bytes(challenge_b64)

    if session_username != username:
        raise HTTPException(status_code=400, detail="Username mismatch")

    try:
        user = User.get_by_id(username)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    # Convert credential from pydantic model to WebAuthn format
    credential = RegistrationCredential(
        id=credential_json.id,
        raw_id=credential_json.rawId,
        response=credential_json.response,
        type=credential_json.type,
    )

    try:
        # Verify the registration response
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            require_user_verification=False,
        )
    except Exception as e:
        logger.error(f"Registration verification failed: {e}")
        raise HTTPException(status_code=400, detail=f"Verification failed: {str(e)}")

    # Get the current credentials list or initialize an empty one
    credentials = user.webauthn_credentials or []

    # Store the new credential
    new_credential = {
        "id": credential_json.id,
        "publicKey": base64.b64encode(verification.credential_public_key).decode(),
        "aaguid": verification.aaguid,
        "sign_count": verification.sign_count,
        "transports": credential_json.transports or ["internal"],
        "created_at": str(int(time.time())),
    }

    credentials.append(new_credential)
    User.set_by_id(username, {"webauthn_credentials": credentials})

    # Clear the session data
    if "webauthn_challenge" in request.session:
        del request.session["webauthn_challenge"]
    if "webauthn_username" in request.session:
        del request.session["webauthn_username"]
    if "webauthn_rp_id" in request.session:
        del request.session["webauthn_rp_id"]
    if "webauthn_origin" in request.session:
        del request.session["webauthn_origin"]
    if "webauthn_admin_registration" in request.session:
        del request.session["webauthn_admin_registration"]

    return {"message": "Registration successful"}


@router.get("/webauthn/authentication-options")
async def get_authentication_options(request: Request, username: str):
    """Get WebAuthn authentication options for a specific user."""
    try:
        user = User.get_by_id(username)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.webauthn_credentials:
        raise HTTPException(
            status_code=400, detail="No WebAuthn credentials found for this user"
        )

    # Get the list of allowed credentials for this user
    allowed_credentials = []
    for cred in user.webauthn_credentials:
        try:
            allowed_credentials.append(
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred["id"]),
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    transports=cred.get("transports", ["internal"]),
                )
            )
        except Exception as e:
            logger.warning(f"Error processing credential: {e}")
            # Skip invalid credentials

    rp_id = get_rp_id_from_request(request)
    rp_origin = get_origin_from_request(request)

    # Generate a random challenge
    challenge = generate_challenge()

    # Generate authentication options
    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=allowed_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    # Store challenge and username in session for verification
    # Store challenge as base64 for session compatibility
    request.session["webauthn_challenge"] = bytes_to_base64url(challenge)
    request.session["webauthn_username"] = username
    request.session["webauthn_rp_id"] = rp_id
    request.session["webauthn_origin"] = rp_origin

    # Convert to JSON response
    return options_to_json(options)


@router.post("/webauthn/authenticate")
async def authenticate_credential(
    request: Request, credential_json: WebAuthnAuthenticationResponse
):
    """Authenticate a user with a WebAuthn credential."""
    # Get saved data from session
    username = request.session.get("webauthn_username")
    challenge_b64 = request.session.get("webauthn_challenge")
    expected_rp_id = request.session.get("webauthn_rp_id")
    expected_origin = request.session.get("webauthn_origin")

    if not username or not challenge_b64 or not expected_rp_id or not expected_origin:
        raise HTTPException(status_code=400, detail="Missing session data")

    # Convert the base64 challenge back to bytes
    challenge = base64url_to_bytes(challenge_b64)

    try:
        user = User.get_by_id(username)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.webauthn_credentials:
        raise HTTPException(
            status_code=400, detail="No WebAuthn credentials found for this user"
        )

    # Find the credential that matches the ID
    credential_record = None
    for cred in user.webauthn_credentials:
        if cred["id"] == credential_json.id:
            credential_record = cred
            break

    if not credential_record:
        raise HTTPException(status_code=400, detail="Credential not found")

    # Convert credential from pydantic model to WebAuthn format
    credential = AuthenticationCredential(
        id=credential_json.id,
        raw_id=credential_json.rawId,
        response=credential_json.response,
        type=credential_json.type,
    )

    # Get the stored public key and sign count
    public_key = base64.b64decode(credential_record["publicKey"])
    stored_sign_count = credential_record.get("sign_count", 0)

    try:
        # Verify the authentication response
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=public_key,
            credential_current_sign_count=stored_sign_count,
            require_user_verification=False,
        )
    except Exception as e:
        logger.error(f"Authentication verification failed: {e}")
        raise HTTPException(status_code=400, detail=f"Verification failed: {str(e)}")

    # Update the sign count
    credentials = user.webauthn_credentials
    for cred in credentials:
        if cred["id"] == credential_json.id:
            cred["sign_count"] = verification.new_sign_count
            break

    # Update the user's credentials
    User.set_by_id(username, {"webauthn_credentials": credentials})

    # Clear the session data
    if "webauthn_challenge" in request.session:
        del request.session["webauthn_challenge"]
    if "webauthn_username" in request.session:
        del request.session["webauthn_username"]
    if "webauthn_rp_id" in request.session:
        del request.session["webauthn_rp_id"]
    if "webauthn_origin" in request.session:
        del request.session["webauthn_origin"]

    # Create a JWT token for the user
    JWT_COOKIE_NAME = request.app.frigate_config.auth.cookie_name
    JWT_COOKIE_SECURE = request.app.frigate_config.auth.cookie_secure
    JWT_SESSION_LENGTH = request.app.frigate_config.auth.session_length

    expiration = int(request.app.time()) + JWT_SESSION_LENGTH
    role = user.role if user.role in ["admin", "viewer"] else "viewer"
    encoded_jwt = create_encoded_jwt(username, role, expiration, request.app.jwt_token)

    response = JSONResponse(
        content={"success": True, "username": username, "role": role}
    )
    set_jwt_cookie(
        response, JWT_COOKIE_NAME, encoded_jwt, expiration, JWT_COOKIE_SECURE
    )

    return response


@router.get(
    "/webauthn/credentials", dependencies=[Depends(require_role(["admin", "viewer"]))]
)
async def get_webauthn_credentials(request: Request):
    """Get WebAuthn credentials for the current user."""
    current_user = await get_current_user(request)
    if isinstance(current_user, JSONResponse):
        raise HTTPException(status_code=401, detail="Unauthorized")

    username = current_user.get("username")

    try:
        user = User.get_by_id(username)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.webauthn_credentials:
        return {"credentials": []}

    # Return simplified credential info (not the keys themselves)
    simplified_credentials = []
    for cred in user.webauthn_credentials:
        simplified_credentials.append(
            {
                "id": cred["id"],
                "created_at": cred.get("created_at", "Unknown"),
                "aaguid": cred.get("aaguid", "Unknown"),
                "transports": cred.get("transports", None),
            }
        )

    return {"credentials": simplified_credentials}


@router.get(
    "/webauthn/credentials/{username}", dependencies=[Depends(require_role(["admin"]))]
)
async def get_webauthn_credentials_for_user(request: Request, username: str):
    """Get WebAuthn credentials for a specific user (admin only)."""
    try:
        user = User.get_by_id(username)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.webauthn_credentials:
        return {"credentials": []}

    # Return simplified credential info
    simplified_credentials = []
    for cred in user.webauthn_credentials:
        simplified_credentials.append(
            {
                "id": cred["id"],
                "created_at": cred.get("created_at", "Unknown"),
                "aaguid": cred.get("aaguid", "Unknown"),
                "transports": cred.get("transports", None),
            }
        )

    return {"credentials": simplified_credentials}


@router.put(
    "/webauthn/credentials", dependencies=[Depends(require_role(["admin", "viewer"]))]
)
async def update_webauthn_credentials(request: Request):
    """Delete all WebAuthn credentials for the current user."""
    current_user = await get_current_user(request)
    if isinstance(current_user, JSONResponse):
        raise HTTPException(status_code=401, detail="Unauthorized")

    username = current_user.get("username")

    try:
        user = User.get_by_id(username)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    # Reset credentials to an empty array
    User.set_by_id(username, {"webauthn_credentials": []})

    return {"message": "All passkeys cleared successfully"}


@router.put(
    "/webauthn/credentials/{username}", dependencies=[Depends(require_role(["admin"]))]
)
async def update_webauthn_credentials_for_user(request: Request, username: str):
    """Delete all WebAuthn credentials for a specific user (admin only)."""
    try:
        user = User.get_by_id(username)
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="User not found")

    # Reset credentials to an empty array
    User.set_by_id(username, {"webauthn_credentials": []})

    return {"message": f"All passkeys for user {username} cleared successfully"}
