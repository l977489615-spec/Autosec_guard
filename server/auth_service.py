from typing import Any, Optional

import jwt


def resolve_user_from_bearer(
    auth_header: Optional[str],
    secret_key: str,
    user_model: Any,
) -> Optional[Any]:
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    try:
        token = auth_header.split(" ", 1)[1]
        token_data = jwt.decode(token, secret_key, algorithms=["HS256"])
        user_id = token_data.get("user_id")
        if not user_id:
            return None
        return user_model.query.filter_by(id=user_id).first()
    except Exception:
        return None
