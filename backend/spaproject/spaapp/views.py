from django.http import JsonResponse
from .models import UserProfile
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.http import require_POST
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError


import logging

logger = logging.getLogger('spaapp')

# Create your views here.
def getUserProfile(request, username):
    try:
        userProfile = UserProfile.objects.get(user__username=username)
        data = {
            "username": userProfile.user.username if userProfile.user else None,
            "email": userProfile.user.email if userProfile.user else None,
            "level": userProfile.level,
            "createdDate": userProfile.createdDate,
            "playCount": userProfile.playCount,
            "winCount": userProfile.winCount
        }
        return JsonResponse(data)
    except UserProfile.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)

@login_required
def userProfile(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        data = {
            "username": request.user.username,
            "email": request.user.email,
            "level": user_profile.level,
            "createdDate": user_profile.createdDate.strftime('%Y-%m-%d %H:%M:%S'),
            "playCount": user_profile.playCount,
            "winCount": user_profile.winCount
        }
        return JsonResponse(data)
    except UserProfile.DoesNotExist:
        return JsonResponse({"error": "User profile not found"}, status=404)

def registerUser(request):
    if request.method == 'POST':
        try:
            data = request.POST
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')

            try:
                validate_password(password, request.user)
            except ValidationError as ve:
                error_message = ' '.join(ve.messages)
                logger.error(f'Password validation error: {error_message}')
                return JsonResponse({'error': error_message}, status=400)

            if User.objects.filter(username=username).exists():
                logger.error('Username already exists error')
                return JsonResponse({'error': 'Username already exists'}, status=400)

            user = User.objects.create(
                username=username,
                email=email,
                password=make_password(password)
            )
            user.save()

            return JsonResponse({'message': 'User created successfully'}, status=201)
        except Exception as e:
            logger.exception('Unexpected error')
            return JsonResponse({'error': str(e)}, status=500)
    else:
        logger.error('Invalid request error')
        return JsonResponse({'error': 'Invalid request'}, status=400)

def loginUser(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        return JsonResponse({'message': 'Login successful'}, status=200)
    else:
        return JsonResponse({'message': 'Invalid username or password'}, status=401)

@login_required
@require_POST
def logoutUser(request):
    logout(request)
    return JsonResponse({'message': 'Logout successful'}, status=200)

@login_required
def deleteUser(request):
    if request.method == 'POST':
        try:
            user = User.objects.get(username=request.user.username)
            username = user.username
            user.delete()
            logout(request)
            return JsonResponse({'message': f'User {username} deleted successfully'}, status=200)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

def check_login_status(request):
    if request.user.is_authenticated:
        return JsonResponse({'is_loggedin': True})
    else:
        return JsonResponse({'is_loggedin': False})
