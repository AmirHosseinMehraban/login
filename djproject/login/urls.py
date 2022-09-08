from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as auth_views
from login import views

urlpatterns = [
    path('', views.signin,name="signin"),
    path('signup',views.signup,name="signup"),
    path('forgot',views.forgot,name="forgot"),
    path('khar',views.page,name='page'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('reset_password/<uidb64>/<token>' ,views.reset_password,name="reset_password"),

    path('newpassword',views.newpassword,name="newpassword"),

    path('reset_password_sent/' ,auth_views.PasswordResetDoneView.as_view(),name="reset_password_sent"),


    path('reset/<uidb64>/<token>/' ,auth_views.PasswordResetConfirmView.as_view(),name="reset"),


    path('reset_password_complete/' ,auth_views.PasswordResetCompleteView.as_view(),name="reset_password_complete"),
]