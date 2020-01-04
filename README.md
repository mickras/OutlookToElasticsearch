# OutlookToElasticsearch
 Script der læser emails fra en Exchange-postkasse og indekserer statistiske data om emailen i Elasticsearch.

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
