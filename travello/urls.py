from django.urls import path
from . import views
from travello.views import index, contact
from django.conf.urls import include, url
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('',views.index,name='index'),
    
    path('contact',views.contact,name='contact'),
    
    path('index',views.index,name='index'),
    
    path('news',views.news,name='news'),
    
    path('about',views.about,name='about'),

    path('register',views.register,name='register'),

    path('signin',views.signin, name='signin'),

    path('send',views.sendandemail,name='index'),

    path('logout_user',views.logout_user,name='logout_user'),

    path('contact_employee',views.contact_employee,name='contact_employee'),

     path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='registration/password_change_done.html'), 
        name='password_change_done'),

    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='registration/password_change.html'), 
        name='password_change'),

    path('password_reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='registration/password_reset_done.html'),
     name='password_reset_done'),

    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),

    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='registration/password_reset_complete.html'),
     name='password_reset_complete'),

      path('forget',views.forget,name='forget'),

      path('subscribe',views.subscribe,name='subscribe'),

      path('poltava',views.poltava,name='poltava'),

      path('vinista',views.vinista,name='vinista'),

      path('kharkiv',views.kharkiv,name='kharkiv'),

      path('ternopil',views.ternopil,name='ternopil'),

      path('gallery',views.gallery,name='gallery'),

      path('developer',views.developer,name='developer'),


]