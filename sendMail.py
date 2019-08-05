import os.path
import pickle

from apiclient import errors
from email.mime.text import MIMEText
from base64 import urlsafe_b64encode
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request


# TODO OPTIONAL delete message from "sent email" on gmail
class SendMail:

    def __init__(self):
        self.SENDER = "theomscproject@gmail.com"
        self.SCOPE = 'https://www.googleapis.com/auth/gmail.compose'  # Allows sending only, not reading

        # Initialize the object for the Gmail API
        # https://developers.google.com/gmail/api/quickstart/python
        # store = file.Storage('credentials.json')
        # creds = store.get()
        # if not creds or creds.invalid:
        #     flow = client.flow_from_clientsecrets('client_secret.json', SCOPE)
        #     creds = tools.run_flow(flow, store)
        # service = build('gmail', 'v1', http=creds.authorize(Http()))

        creds = None
        # The file token.pickle stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', self.SCOPE)
                creds = flow.run_local_server()
            # Save the credentials for the next run
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)

        self.service = build('gmail', 'v1', credentials=creds)

    # https://developers.google.com/gmail/api/guides/sending
    @staticmethod
    def create_message(sender, to, subject, message_text):
        """Create a message for an email.
      Args:
        sender: Email address of the sender.
        to: Email address of the receiver.
        subject: The subject of the email message.
        message_text: The text of the email message.
      Returns:
        An object containing a base64url encoded email object.
      """
        message = MIMEText(message_text)
        message['to'] = to
        message['from'] = sender
        message['subject'] = subject
        encoded_message = urlsafe_b64encode(message.as_bytes())
        return {'raw': encoded_message.decode()}

    # https://developers.google.com/gmail/api/guides/sending
    @staticmethod
    def send_message(service, user_id, message):
        """Send an email message.
      Args:
        service: Authorized Gmail API service instance.
        user_id: User's email address. The special value "me"
        can be used to indicate the authenticated user.
        message: Message to be sent.
      Returns:
        Sent Message.
      """
        try:
            message = (service.users().messages().send(userId=user_id, body=message)
                       .execute())
            print('Message Id: %s' % message['id'])
            return message
        except errors.HttpError as error:
            # except:
            print('An error occurred: %s' % error)


# RECIPIENT = "td37@hw.ac.uk"
# SUBJECT = "deletion_test"
# CONTENT = "hello :)"
#
# sm = SendMail()
# raw_msg = sm.create_message(sm.SENDER, RECIPIENT, SUBJECT, CONTENT)
# sm.send_message(sm.service, "me", raw_msg)
