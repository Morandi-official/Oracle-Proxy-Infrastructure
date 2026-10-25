from django.urls import include, path
from django.conf import settings
from console import views, client_api, transports

urlpatterns = [
    path('privacy-check/',views.privacy_check),
    path('privacy-check.js',views.privacy_asset,{'name':'privacy.js'}),
    path('privacy-check.css',views.privacy_asset,{'name':'style.css'}),
    path('', views.dashboard, name='dashboard'),
    path('login/', views.login_page, name='login'),
    path('logout/', views.logout_page, name='logout'),
    path('api/client/login', client_api.login),
    path('api/client/authenticate', client_api.authenticate),
    path('api/client/enroll', client_api.enroll),
    path('api/client/presence', client_api.presence),
    path('api/client/state', client_api.state),
    path('api/client/quic-certificate', transports.public_certificate),
    path('api/client/logout', client_api.logout),
    path('api/status', views.status),
    path('api/audit', views.audit),
    path('api/control', views.management),
    path('api/users/<uuid:user_id>/usage', views.user_usage),
    path('api/health', views.health),
    path('usage.js', views.asset, {'name': 'usage.js'}),
    path('app.js', views.asset, {'name': 'app.js'}),
    path('style.css', views.asset, {'name': 'style.css'}),
]

if settings.ADMIN_AUTH_MODE != 'local':
    urlpatterns.append(path('accounts/',include('allauth.urls')))
