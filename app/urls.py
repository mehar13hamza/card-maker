from django.urls import path
from django.contrib.auth import views as auth_views
# current directory
from . import views
from django.conf.urls import url



urlpatterns = [
    url(r'^$', views.home, name = 'home'),
    url(r'^login/', views.loginUser, name = 'login'),
    url(r'^signup/', views.signupUser, name='signup'),  
	path('logout/', views.logoutUser, name="logout"),
    url(r'^new/', views.new, name='new'),
    url(r'^checkout/', views.checkout, name = 'checkout'),

]