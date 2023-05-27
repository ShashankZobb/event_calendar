from django.shortcuts import redirect
from django.http import JsonResponse, HttpResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
import os


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "calendars/credential.json"

SCOPES = ['https://www.googleapis.com/auth/calendar',
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile',
          'https://www.googleapis.com/auth/calendar.readonly',
          'openid']
REDIRECT_URL = 'https://google-calender.shashankzobb.repl.co/rest/v1/calendar/redirect/'



@api_view(['GET'])
def GoogleCalendarInitView(request):
    try:
      # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
      flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
          CLIENT_SECRETS_FILE, scopes=SCOPES)
  
      flow.redirect_uri = REDIRECT_URL
  
      authorization_url, state = flow.authorization_url( 
                                 access_type='offline',
                                 include_granted_scopes='true')
  
      request.session['state'] = state
      return redirect(authorization_url)
    except Exception as ex:
      print("Error: ", ex)
      return HttpResponse("Sorry we were unable to process your request.")

@api_view(['GET'])
def GoogleCalendarRedirectView(request):
  try:
      state = request.session['state']
      flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
          CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
      flow.redirect_uri = REDIRECT_URL
  
      authorization_response = request.get_full_path()
      flow.fetch_token(authorization_response=authorization_response)
  
  
      # Save credentials back to session in case access token was refreshed.
      credentials = flow.credentials
      request.session['credentials'] = credentials_to_dict(credentials)
  
      # Check if credentials are in session
      if 'credentials' not in request.session:
          return redirect('v1/calendar/init')
  
      # Load credentials from the session.
      creds = google.oauth2.credentials.Credentials(
          **request.session['credentials'])
      
      service = build('calendar', 'v3', credentials=creds, static_discovery=False)
  
      # Returns the calendars on the user's calendar list
      calendar_list = service.calendarList().list().execute()
  
      # Getting user ID which is his/her email address
      calendar_id = calendar_list['items'][0]['id']
      # Getting all events associated with a user ID (email address)
      events  = service.events().list(calendarId=calendar_id).execute()
  
      events_list_append = []
      for events_list in events['items']:
          events_list_append.append(events_list)
      return JsonResponse({"events": events_list_append}, safe=False, status=200)
  except Exception as ex:
      print("Error: ", ex)
      return HttpResponse("Sorry we were unable to process your request.")
    

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}