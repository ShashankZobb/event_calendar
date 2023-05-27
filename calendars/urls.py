from django.urls import path
from . import views
urlpatterns = [
  path('init/', views.GoogleCalendarInitView),
  path('redirect/', views.GoogleCalendarRedirectView),  
]
