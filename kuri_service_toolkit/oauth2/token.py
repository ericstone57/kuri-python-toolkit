from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, ExpiredSignatureError, JWTError
from jose.exceptions import JWTClaimsError
import os

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


def token_validate(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(
            token,
            os.getenv('OAUTH_PUBLIC_KEY'),
            algorithms=['ES256'],
            audience=os.getenv('UC_AUDIENCE'),
            issuer=f'{os.getenv("UC_DOMAIN")}/token/{os.getenv("UC_APPID")}/'
        )
        if not ('cid' in payload and payload['cid'] == os.getenv('UC_CLIENT_ID')):
            raise HTTPException(
                status_code=401, detail='application id invalid.')
    except (JWTError, ExpiredSignatureError, JWTClaimsError) as err:
        raise HTTPException(status_code=401, detail=str(err))
    else:
        return True
