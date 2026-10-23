from django.urls import include, path
from console import views, client_api, transports

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', views.login_page, name='login'),
    path('accounts/', include('allauth.urls')),
    path('api/client/login', client_api.login),
    path('api/client/state', client_api.state),
    path('api/client/quic-certificate', transports.public_certificate),
    path('api/client/logout', client_api.logout),
    path('api/status', views.status),
    path('api/audit', views.audit),
    path('api/control', views.management),
    path('api/health', views.health),
    path('app.js', views.asset, {'name': 'app.js'}),
    path('style.css', views.asset, {'name': 'style.css'}),
]
