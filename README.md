# PasswordManager

Projekt bezpiecznej aplikacji webowej stworzonej w ramach przedmiotu 'Ochrona danych w systemach informatycznych'.

#Zabezpieczenia i funkcjonalności:

restrykcyjna walidacja danych pochodzących z formularza login-hasło, 

przechowywanie hasła chronione funkcją hash, solą i pieprzem,

możliwość umieszczenia na serwerze haseł dostępnych prywatnie lub dla określonych użytkowników,

szyfrowanie symetryczne przechowywanych haseł,

możliwość zmiany hasła,

możliwość odzyskania dostępu w przypadku utraty hasła,

dodatkowa kontrola spójności sesji (przeciw atakom XSRF),

wielokrotne wykorzystanie funkcji hash, żeby wydłużyć ataki brute-force na hash,

weryfikacja liczby nieudanych prób logowania,

dodanie opóźnienia przy weryfikacji hasła w celu wydłużenia ataków zdalnych,

sprawdzanie jakości hasła (jego entropii).
