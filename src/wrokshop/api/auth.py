from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

from ..models.auth import Token, UserCreate, User
from ..services.auth import AuthServices, get_current_user

router = APIRouter(
    prefix='/auth'
)


@router.post('/sign-up/', response_model=Token)
def registrate_new_user(
        user_data: UserCreate,
        auth_service: AuthServices = Depends()
):
    return auth_service.register_new_user(user_data=user_data)


@router.post('/sign-in/', response_model=Token)
def login_user(
        form: OAuth2PasswordRequestForm = Depends(),
        auth_service: AuthServices = Depends()
):
    return auth_service.login_user(username=form.username, password=form.password)


@router.get('/get-current-user/', response_model=User)
def get_user(
        user: User = Depends(get_current_user)
):
    return user
