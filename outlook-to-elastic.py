# === Outlook-statistik til Elasticsearch ===
"""
Dette script læser alle indkommende emails i en Exchange postkasse og sender
statistiske data til Elasticsearch. Tanken er at scriptet køres via cronjob f.eks.
1-2 gange pr. time, men det kan i princippet køres så ofte eller sjældent som
man ønsker. Hvis post slettes fra postkassen før scriptet køres, vil dette
selvfølgelig ikke blive registreret og mailen bliver ikke en del af statistikken.

Når scriptet køres, logges timestamp til en tekstfil. Næste gang scriptet køres,
læses dette timestamp, og der hentes kun email fra dette timestamp og frem til
nuværende klokkeslet. IDen på emailen bruges som ID på dokumentet der indekseres
i Elasticsearch, så der er ingen fare for at en email bliver registreret flere
gange. Skulle scriptet komme til at læse samme email igen, vil det eksisterende
dokument i Elasticsearch simpelthen bliver overskrevet med det nye dokument.
"""
import datetime
import json
import os
import sys
from datetime import timedelta

import bugsnag
import pytz
from cryptography.fernet import Fernet
from elasticsearch import Elasticsearch
from exchangelib import (Account, Credentials, EWSDateTime, Folder, Message)

import settings.settings as settings
from CommonFunctions import common_functions

# Indstillinger
elasticsearch_host      = "eshost01"
elasticsearch_port      = 9200
elasticsearch_doctype   = "_doc"
elasticsearch_index     = "myesindex"
outlook_account_email   = "my@email.com"
outlook_account_pwd     = "mypassword"
outlook_mailbox         = "email@email.com"
use_fernet_encryption   = True
fernet_encryption_key   = os.environ['MyFernetkey']
timestamp_file_path     = "timestamp.log"

class Email:
    """Klassen "email" bruges til at lave et email-objekt ud fra en email fra
    Exchange. Klassen tager et Exchangelib-objekt som input, når objektet
    oprettes: mail_obj = email(exchangelib_obj).
    """
    def __init__(self, mailitem):
        self.subject        = mailitem.subject
        self.sender_name    = mailitem.sender.name
        self.sender_email   = mailitem.sender.email_address
        self.mailbox_type   = mailitem.sender.mailbox_type
        self.received       = mailitem.datetime_received,
        self.attachment     = mailitem.attachments
        self.message_id     = mailitem.message_id.replace("<", "").replace(">", "")

    def received_timestamp(self):
        """Konverterer timestamp for hvornår emailen er modtaget, som er et
        EWSDatetime-objekt, til en string som har et format som Elasticsearch
        kan tolke som et timestamp"""
        ts = str(self.received[0])
        ts = ts[:19]
        ts = ts.replace("-", "/")
        return ts

    def current_timestamp(self):
        """Returnerer helt enkelt nuværende klokkeslet som et timestamp som
        Elasticsearch tolker som et timestamp"""
        return (datetime.datetime.now()).strftime("%Y/%m/%d %H:%M:%S")

    def get_domain(self):
        """Returnerer domæne-delen af afsender-emailadressen"""
        domain = self.sender_email.split("@")
        if len(domain) > 0:
            return domain[1]
        else:
            return Null

    def attachment_count(self):
        """Returnerer antal attachment i emailen, som et heltal"""
        return len(self.attachment)

    def json(self):
        """Returnerer en JSON-streng med de data der skal indekseres
        i Elasticsearch"""
        json = {
            "timestamp":        self.current_timestamp(),
            "received":         self.received_timestamp(),
            "sender_name":      self.sender_name,
            "sender_email":     self.sender_email,
            "domain":           self.get_domain(),
            "mailbox_type":     self.mailbox_type,
            "subject":          self.subject,
            "message_id":       self.message_id,
            "attachment_count": self.attachment_count()
        }
        return json

def connect_to_outlook():
    if use_fernet_encryption:
        # Hvis password til Exchange-kontoen er krypteret med fernet:
        cipher_suite = Fernet(fernet_encryption_key)
        pwd = (cipher_suite.decrypt(str.encode(outlook_account_pwd))).decode()
    else:
        # Hvis password til Exchange-kontoen er ukrypteret:
        pwd = outlook_account_pwd

    credentials = Credentials(outlook_account_email, pwd)
    account = Account(outlook_mailbox, credentials=credentials, autodiscover=True)
    return account

def send_to_elasticsearch(json_body, message_id):
    es = Elasticsearch([{'host':elasticsearch_host,'port':elasticsearch_port}])
    result = es.index(index=elasticsearch_index, id=message_id, doc_type=elasticsearch_doctype, body=json_body)
    return result

try:
    account = connect_to_outlook()

    if os.path.isfile(timestamp_file_path):
        # Hent timestamp for sidste kørsel af scriptet, fra timestamp-filen
        f = open(timestamp_file_path, "r")
        old_timestamp = f.read()
        f.close()

        # Fjern evt. linieskift og konverter til et Python dato-objekt
        old_timestamp = old_timestamp.replace("\n", "")
        from_timestamp = datetime.datetime.strptime(old_timestamp, "%Y-%m-%d %H:%M:%S.%f")

        current_timestamp = datetime.datetime.now()

        # Først beregner vi tiden siden forrige kørsel, i sekunder
        timedif = (current_timestamp - from_timestamp).total_seconds()

        # Så beregner vi det nøjagtige klokkeslet for forrige kørsel
        since = current_timestamp - timedelta(seconds=timedif)

        # klokkeslettet konverteres til et EWSDateTime-objekt, for at vi kan
        # bruge det i filtreringen i dataene vi får fra Exchange.
        pytz_tz = pytz.timezone('Europe/Copenhagen')
        py_dt = pytz_tz.localize(since)
        since = EWSDateTime.from_datetime(py_dt)

        # Hent alle meldinger fra Exchange, som er nyere end klokkeslet for sidst
        # scriptet blev kørt
        for item in account.inbox.all().filter(datetime_received__gt=since).order_by('-datetime_received'):
            # Lav et mail-objekt ud fra emailen fra outlook
            mail = Email(item)
            print(json.dumps(mail.json(), indent=4))

            # indekser emailen i Elasticsearch
            result = send_to_elasticsearch(mail.json(), mail.message_id)
            print(json.dumps(result, indent=4))

        # Gem det nye klokkeslet til fil, så vi ved fra hvilket tidspunkt vi
        # skal hente emails fra Exchange, næste gang scriptet køres
        f = open(timestamp_file_path, "w")
        f.write(str(current_timestamp))
        f.close()

except Exception as e:
  fejlmelding = (
      "Error on line {}".format(sys.exc_info()[-1].tb_lineno),
      type(e).__name__,
      e,
  )
  print(fejlmelding)
