# =========================================================
# NATHO — Plateforme d'apprentissage de l'allemand A1
# Fichier unique • Python + Flask + SQLite
# Version finale : Code complet avec toutes tes données
# =========================================================

import os
import sqlite3
import hashlib
import secrets
import json
import random
import re
import stat
from html import escape as h
from datetime import datetime
from functools import wraps
from flask import (Flask, request, session, redirect, url_for,
                   render_template_string, g, flash, jsonify,
                   get_flashed_messages, send_file, make_response)

try:
    from gtts import gTTS
    TTS_OK = True
except Exception:
    gTTS = None
    TTS_OK = False

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------
APP_SECRET = os.environ.get("NATHO_SECRET", "change-me-in-prod-" + secrets.token_hex(8))
DATA_DIR = "/app/data"
DB_PATH = os.path.join(DATA_DIR, "natho.db")

try:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.chmod(DATA_DIR, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
except Exception as e:
    print("Attention dossier data :", e)

app = Flask(__name__)
app.secret_key = APP_SECRET

# ---------------------------------------------------------
# BASE DE DONNÉES
# ---------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def hash_pwd(pwd: str) -> str:
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()

def init_db():
    try:
        db = sqlite3.connect(DB_PATH)
        c = db.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")

        # FORCE L'ADMINISTRATEUR AVEC TON MOT DE PASSE
        admin_email = "admin@natho.com"
        admin_pwd = "Achilled@vy2015"
        
        c.execute("SELECT * FROM users WHERE email=?", (admin_email,))
        admin_row = c.fetchone()
        
        if not admin_row:
            c.execute("INSERT INTO users(name,email,password,is_admin) VALUES(?,?,?,1)",
                      ("Admin NATHO", admin_email, hash_pwd(admin_pwd)))
            print("✅ Compte Admin créé.")
        else:
            c.execute("UPDATE users SET password=?, is_admin=1 WHERE email=?", 
                      (hash_pwd(admin_pwd), admin_email))
            print("✅ Compte Admin mis à jour.")

        # -----------------------------------------------------
        # TABLES ET CONTENU
        # -----------------------------------------------------
        c.execute("""CREATE TABLE IF NOT EXISTS lessons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            level TEXT DEFAULT 'A1',
            title TEXT NOT NULL,
            french TEXT NOT NULL,
            german TEXT NOT NULL,
            order_index INTEGER DEFAULT 0
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS vocab (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            german TEXT NOT NULL,
            french TEXT NOT NULL
        )""")
        
        c.execute("""CREATE TABLE IF NOT EXISTS dialogues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            lines_json TEXT NOT NULL
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            lesson_id INTEGER NOT NULL,
            listened INTEGER DEFAULT 0,
            completed INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, lesson_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(lesson_id) REFERENCES lessons(id)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS goethe_exam (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            result_json TEXT NOT NULL,
            taken_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

        # Remplissage initial
        c.execute("SELECT COUNT(*) FROM lessons")
        if c.fetchone()[0] == 0:
            seed_lessons(c)
            seed_vocab(c)
            seed_dialogues(c)
            seed_numbers(c)

        db.commit()
        db.close()
        print("✅ Base de données initialisée.")
    except Exception as e:
        print("❌ Erreur d'initialisation :", e)

# ---------------------------------------------------------
# CONTENU PÉDAGOGIQUE (Tes 300 phrases et 320 mots)
# ---------------------------------------------------------
def seed_lessons(cursor):
    data = [
        ("Salutations", "Hallo!", "Salut ! / Bonjour !"), ("Salutations", "Guten Morgen!", "Bonjour ! (le matin)"),
        ("Salutations", "Guten Tag!", "Bonjour !"), ("Salutations", "Guten Abend!", "Bonsoir !"),
        ("Salutations", "Gute Nacht!", "Bonne nuit !"), ("Salutations", "Wie geht es dir?", "Comment vas-tu ?"),
        ("Salutations", "Wie geht es Ihnen?", "Comment allez-vous ?"), ("Salutations", "Mir geht es gut, danke.", "Je vais bien, merci."),
        ("Salutations", "Und dir?", "Et toi ?"), ("Salutations", "Auf Wiedersehen!", "Au revoir !"),
        ("Salutations", "Guten Tag, Frau Müller!", "Bonjour, Madame Müller !"), ("Salutations", "Guten Tag, Herr Schmidt!", "Bonjour, Monsieur Schmidt !"),
        ("Salutations", "Hallo, wie geht's?", "Salut, ça va ?"), ("Salutations", "Danke, sehr gut.", "Merci, très bien."),
        ("Salutations", "Es geht so.", "Comme ci, comme ça."), ("Salutations", "Bis später!", "À tout à l'heure !"),
        ("Salutations", "Tschüs!", "Salut ! (au revoir)"), ("Salutations", "Schönen Tag noch!", "Bonne journée !"),
        ("Se présenter", "Ich heiße Davy.", "Je m'appelle Davy."), ("Se présenter", "Wie heißt du?", "Comment t'appelles-tu ?"),
        ("Se présenter", "Mein Name ist Davy.", "Mon nom est Davy."), ("Se présenter", "Freut mich.", "Enchanté."),
        ("Se présenter", "Ich komme aus Kamerun.", "Je viens du Cameroun."), ("Se présenter", "Woher kommst du?", "D'où viens-tu ?"),
        ("Se présenter", "Ich wohne in Paris.", "J'habite à Paris."), ("Se présenter", "Wo wohnst du?", "Où habites-tu ?"),
        ("Se présenter", "Ich bin neu hier.", "Je suis nouveau ici."), ("Se présenter", "Ich bin Student.", "Je suis étudiant."),
        ("Se présenter", "Wie alt bist du?", "Quel âge as-tu ?"), ("Se présenter", "Ich bin dreißig Jahre alt.", "J'ai trente ans."),
        ("Se présenter", "Ich spreche Französisch und Englisch.", "Je parle français et anglais."), ("Se présenter", "Meine Muttersprache ist Französisch.", "Ma langue maternelle est le français."),
        ("Se présenter", "Ich komme aus Yaoundé.", "Je viens de Yaoundé."), ("Se présenter", "Ich bin ledig.", "Je suis célibataire."),
        ("Se présenter", "Sehr erfreut, Sie kennenzulernen.", "Très heureux de faire votre connaissance."), ("Se présenter", "Darf ich mich vorstellen?", "Puis-je me présenter ?"),
        ("Se présenter", "Das ist mein Freund Paul.", "Voici mon ami Paul."),
        ("Comprendre", "Ich verstehe.", "Je comprends."), ("Comprendre", "Ich verstehe nicht.", "Je ne comprends pas."),
        ("Comprendre", "Bitte wiederholen Sie.", "Veuillez répéter, s'il vous plaît."), ("Comprendre", "Kannst du das wiederholen?", "Peux-tu répéter ?"),
        ("Comprendre", "Langsamer, bitte.", "Plus lentement, s'il vous plaît."), ("Comprendre", "Was bedeutet das?", "Qu'est-ce que cela signifie ?"),
        ("Comprendre", "Wie sagt man das auf Deutsch?", "Comment dit-on cela en allemand ?"), ("Comprendre", "Ich lerne Deutsch.", "J'apprends l'allemand."),
        ("Comprendre", "Ich spreche ein bisschen Deutsch.", "Je parle un peu allemand."), ("Comprendre", "Noch einmal, bitte.", "Encore une fois, s'il vous plaît."),
        ("Comprendre", "Sprechen Sie Englisch?", "Parlez-vous anglais ?"), ("Comprendre", "Wie schreibt man das?", "Comment cela s'écrit-il ?"),
        ("Comprendre", "Das ist richtig.", "C'est correct."), ("Comprendre", "Das ist falsch.", "C'est faux."),
        ("Comprendre", "Ich weiß nicht.", "Je ne sais pas."), ("Comprendre", "Ich habe verstanden.", "J'ai compris."),
        ("Comprendre", "Was heißt das auf Französisch?", "Que veut dire cela en français ?"),
        ("Questions", "Was ist das?", "Qu'est-ce que c'est ?"), ("Questions", "Wer ist das?", "Qui est-ce ?"),
        ("Questions", "Wo ist die Toilette?", "Où sont les toilettes ?"), ("Questions", "Wann kommst du?", "Quand viens-tu ?"),
        ("Questions", "Warum?", "Pourquoi ?"), ("Questions", "Wie viel kostet das?", "Combien cela coûte-t-il ?"),
        ("Questions", "Wie spät ist es?", "Quelle heure est-il ?"), ("Questions", "Kannst du mir helfen?", "Peux-tu m'aider ?"),
        ("Questions", "Wie bitte?", "Pardon ? / Comment ?"), ("Questions", "Wo wohnen Sie?", "Où habitez-vous ?"),
        ("Questions", "Wie komme ich zum Bahnhof?", "Comment aller à la gare ?"), ("Questions", "Wie lange dauert das?", "Combien de temps cela dure-t-il ?"),
        ("Questions", "Wem gehört das?", "À qui est-ce ?"), ("Questions", "Was möchten Sie trinken?", "Que souhaitez-vous boire ?"),
        ("Questions", "Gibt es hier ein Café?", "Y a-t-il un café ici ?"), ("Questions", "Ist hier noch frei?", "Est-ce libre ici ?"),
        ("Questions", "Wohin gehst du?", "Où vas-tu ?"),
        ("Famille", "Das ist meine Familie.", "Voici ma famille."), ("Famille", "Das ist mein Bruder.", "Voici mon frère."),
        ("Famille", "Das ist meine Schwester.", "Voici ma sœur."), ("Famille", "Ich habe zwei Kinder.", "J'ai deux enfants."),
        ("Famille", "Bist du verheiratet?", "Es-tu marié(e) ?"), ("Famille", "Meine Eltern wohnen hier.", "Mes parents habitent ici."),
        ("Famille", "Das ist mein Vater.", "Voici mon père."), ("Famille", "Das ist meine Mutter.", "Voici ma mère."),
        ("Famille", "Mein Onkel wohnt in Berlin.", "Mon oncle habite à Berlin."), ("Famille", "Meine Tante ist Ärztin.", "Ma tante est médecin."),
        ("Famille", "Ich habe einen Cousin.", "J'ai un cousin."), ("Famille", "Wie viele Geschwister hast du?", "Combien de frères et sœurs as-tu ?"),
        ("Famille", "Mein Sohn ist fünf Jahre alt.", "Mon fils a cinq ans."),
        ("Maison", "Ich bin zu Hause.", "Je suis à la maison."), ("Maison", "Komm bitte herein.", "Entre, s'il te plaît."),
        ("Maison", "Mach die Tür zu.", "Ferme la porte."), ("Maison", "Öffne bitte das Fenster.", "Ouvre la fenêtre, s'il te plaît."),
        ("Maison", "Die Küche ist sauber.", "La cuisine est propre."), ("Maison", "Wo ist mein Schlüssel?", "Où est ma clé ?"),
        ("Maison", "Das Zimmer ist groß.", "La chambre est grande."), ("Maison", "Die Wohnung ist klein.", "L'appartement est petit."),
        ("Maison", "Ich wohne in einem Haus.", "J'habite dans une maison."), ("Maison", "Mach bitte das Licht an.", "Allume la lumière, s'il te plaît."),
        ("Maison", "Mach bitte das Licht aus.", "Éteins la lumière, s'il te plaît."), ("Maison", "Die Miete ist zu hoch.", "Le loyer est trop élevé."),
        ("Maison", "Wo ist der Kühlschrank?", "Où est le réfrigérateur ?"),
        ("Repas", "Ich habe Hunger.", "J'ai faim."), ("Repas", "Ich habe Durst.", "J'ai soif."),
        ("Repas", "Guten Appetit!", "Bon appétit !"), ("Repas", "Möchtest du Wasser?", "Veux-tu de l'eau ?"),
        ("Repas", "Ich trinke Kaffee.", "Je bois du café."), ("Repas", "Die Rechnung, bitte.", "L'addition, s'il vous plaît."),
        ("Repas", "Das schmeckt gut.", "C'est bon."), ("Repas", "Ich esse gern Reis.", "J'aime manger du riz."),
        ("Repas", "Ich esse kein Fleisch.", "Je ne mange pas de viande."), ("Repas", "Ich koche heute Abend.", "Je cuisine ce soir."),
        ("Repas", "Noch ein Glas Wasser, bitte.", "Encore un verre d'eau, s'il vous plaît."), ("Repas", "Ich bin satt.", "Je n'ai plus faim."),
        ("Repas", "Das Essen ist fertig.", "Le repas est prêt."), ("Repas", "Ich möchte einen Tee, bitte.", "Je voudrais un thé, s'il vous plaît."),
        ("Restaurant", "Haben Sie einen Tisch frei?", "Avez-vous une table libre ?"), ("Restaurant", "Ich hätte gern die Speisekarte.", "Je voudrais le menu."),
        ("Restaurant", "Was empfehlen Sie?", "Que recommandez-vous ?"), ("Restaurant", "Ist das vegetarisch?", "Est-ce végétarien ?"),
        ("Restaurant", "Kann ich mit Karte bezahlen?", "Puis-je payer par carte ?"), ("Restaurant", "Einen Tisch für zwei Personen, bitte.", "Une table pour deux personnes, s'il vous plaît."),
        ("Restaurant", "Ich nehme die Suppe.", "Je prends la soupe."), ("Restaurant", "Zahlen, bitte!", "L'addition, s'il vous plaît !"),
        ("Restaurant", "Zusammen oder getrennt?", "Ensemble ou séparément ?"), ("Restaurant", "Das Essen war sehr lecker.", "Le repas était très délicieux."),
        ("Achats", "Ich möchte das kaufen.", "Je voudrais acheter cela."), ("Achats", "Das ist zu teuer.", "C'est trop cher."),
        ("Achats", "Kann ich das anprobieren?", "Puis-je essayer cela ?"), ("Achats", "Wo ist die Kasse?", "Où est la caisse ?"),
        ("Achats", "Ich nehme das.", "Je prends cela."), ("Achats", "Was kostet das Brot?", "Combien coûte le pain ?"),
        ("Achats", "Haben Sie das in Blau?", "L'avez-vous en bleu ?"), ("Achats", "Das ist zu groß.", "C'est trop grand."),
        ("Achats", "Das ist zu klein.", "C'est trop petit."), ("Achats", "Ich suche eine Jacke.", "Je cherche une veste."),
        ("Achats", "Ich zahle bar.", "Je paie en espèces."), ("Achats", "Wann öffnet das Geschäft?", "Quand le magasin ouvre-t-il ?"),
        ("Achats", "Kann ich eine Quittung haben?", "Puis-je avoir un reçu ?"),
        ("Transport", "Wo ist die Bushaltestelle?", "Où est l'arrêt de bus ?"), ("Transport", "Wann fährt der Zug?", "Quand part le train ?"),
        ("Transport", "Eine Fahrkarte nach Berlin, bitte.", "Un billet pour Berlin, s'il vous plaît."), ("Transport", "Wo muss ich umsteigen?", "Où dois-je changer ?"),
        ("Transport", "Der Zug hat Verspätung.", "Le train a du retard."), ("Transport", "Ich fahre mit dem Bus.", "Je prends le bus."),
        ("Transport", "Ich gehe zu Fuß.", "Je vais à pied."), ("Transport", "Von welchem Gleis fährt der Zug?", "De quel quai part le train ?"),
        ("Transport", "Wann kommt der Bus an?", "Quand le bus arrive-t-il ?"), ("Transport", "Einmal hin und zurück, bitte.", "Un aller-retour, s'il vous plaît."),
        ("Transport", "Ist dieser Platz frei?", "Cette place est-elle libre ?"), ("Transport", "Wo ist der Flughafen?", "Où est l'aéroport ?"),
        ("Orientation", "Entschuldigung, wo ist das Zentrum?", "Excusez-moi, où est le centre ?"), ("Orientation", "Gehen Sie geradeaus.", "Allez tout droit."),
        ("Orientation", "Biegen Sie links ab.", "Tournez à gauche."), ("Orientation", "Biegen Sie rechts ab.", "Tournez à droite."),
        ("Orientation", "Es ist in der Nähe.", "C'est à proximité."), ("Orientation", "Wie komme ich zur Post?", "Comment aller à la poste ?"),
        ("Orientation", "Die Bank ist neben dem Supermarkt.", "La banque est à côté du supermarché."), ("Orientation", "Gehen Sie die erste Straße links.", "Prenez la première rue à gauche."),
        ("Orientation", "Es ist nicht weit von hier.", "Ce n'est pas loin d'ici."), ("Orientation", "Die Apotheke ist an der Ecke.", "La pharmacie est au coin."),
        ("Travail", "Was machst du beruflich?", "Quelle est ta profession ?"), ("Travail", "Ich arbeite heute.", "Je travaille aujourd'hui."),
        ("Travail", "Ich suche Arbeit.", "Je cherche du travail."), ("Travail", "Ich habe eine Frage.", "J'ai une question."),
        ("Travail", "Ich mache meine Hausaufgaben.", "Je fais mes devoirs."), ("Travail", "Ich arbeite in einem Büro.", "Je travaille dans un bureau."),
        ("Travail", "Mein Chef ist nett.", "Mon chef est sympa."), ("Travail", "Ich habe heute frei.", "Je suis en congé aujourd'hui."),
        ("Travail", "Ich habe viel Arbeit.", "J'ai beaucoup de travail."), ("Travail", "Die Arbeit beginnt um acht Uhr.", "Le travail commence à huit heures."),
        ("Travail", "Ich bin Ingenieur.", "Je suis ingénieur."), ("Travail", "Ich schreibe eine E-Mail.", "J'écris un e-mail."),
        ("École", "Ich gehe in die Schule.", "Je vais à l'école."), ("École", "Ich besuche einen Deutschkurs.", "Je suis un cours d'allemand."),
        ("École", "Der Lehrer erklärt die Grammatik.", "L'enseignant explique la grammaire."), ("École", "Öffnet bitte das Buch auf Seite zehn.", "Ouvrez le livre à la page dix."),
        ("École", "Hört bitte zu.", "Écoutez, s'il vous plaît."), ("École", "Ich habe morgen eine Prüfung.", "J'ai un examen demain."),
        ("École", "Ich lerne jeden Tag Vokabeln.", "J'apprends du vocabulaire tous les jours."),
        ("Temps", "Es ist acht Uhr.", "Il est huit heures."), ("Temps", "Heute habe ich Zeit.", "Aujourd'hui, j'ai le temps."),
        ("Temps", "Morgen bin ich frei.", "Demain, je suis libre."), ("Temps", "Bis morgen!", "À demain !"),
        ("Temps", "Wann treffen wir uns?", "Quand nous retrouvons-nous ?"), ("Temps", "Heute ist Montag.", "Aujourd'hui, c'est lundi."),
        ("Temps", "Welcher Tag ist heute?", "Quel jour sommes-nous ?"), ("Temps", "Morgen ist Dienstag.", "Demain, c'est mardi."),
        ("Temps", "Am Wochenende habe ich frei.", "Le week-end, je suis libre."), ("Temps", "Wann hast du Geburtstag?", "Quand est ton anniversaire ?"),
        ("Temps", "Gestern war ich zu Hause.", "Hier, j'étais à la maison."), ("Temps", "Es ist Viertel nach zehn.", "Il est dix heures et quart."),
        ("Temps", "Es ist halb drei.", "Il est deux heures et demie."), ("Temps", "Um wie viel Uhr beginnt der Film?", "À quelle heure commence le film ?"),
        ("Météo", "Wie ist das Wetter heute?", "Quel temps fait-il aujourd'hui ?"), ("Météo", "Es ist sonnig.", "Il y a du soleil."),
        ("Météo", "Es regnet.", "Il pleut."), ("Météo", "Es ist kalt.", "Il fait froid."),
        ("Météo", "Es schneit.", "Il neige."), ("Météo", "Es ist heiß.", "Il fait chaud."),
        ("Météo", "Es ist windig.", "Il y a du vent."), ("Météo", "Die Sonne scheint.", "Le soleil brille."),
        ("Météo", "Heute sind zwanzig Grad.", "Aujourd'hui, il fait vingt degrés."), ("Météo", "Nimm einen Regenschirm mit.", "Prends un parapluie."),
        ("Météo", "Im Winter ist es sehr kalt.", "En hiver, il fait très froid."),
        ("Émotions", "Wie fühlst du dich?", "Comment te sens-tu ?"), ("Émotions", "Ich bin müde.", "Je suis fatigué(e)."),
        ("Émotions", "Ich bin krank.", "Je suis malade."), ("Émotions", "Ich habe Kopfschmerzen.", "J'ai mal à la tête."),
        ("Émotions", "Ich brauche einen Arzt.", "J'ai besoin d'un médecin."), ("Émotions", "Mir ist schlecht.", "J'ai mal au cœur."),
        ("Émotions", "Ich habe Bauchschmerzen.", "J'ai mal au ventre."), ("Émotions", "Ich habe Fieber.", "J'ai de la fièvre."),
        ("Émotions", "Ich habe Halsschmerzen.", "J'ai mal à la gorge."), ("Émotions", "Mein Rücken tut weh.", "J'ai mal au dos."),
        ("Émotions", "Ich muss zum Arzt gehen.", "Je dois aller chez le médecin."), ("Émotions", "Ich brauche einen Termin.", "J'ai besoin d'un rendez-vous."),
        ("Émotions", "Gute Besserung!", "Bon rétablissement !"), ("Émotions", "Ich fühle mich besser.", "Je me sens mieux."),
        ("Émotions", "Wie oft muss ich das nehmen?", "Combien de fois dois-je prendre cela ?"), ("Émotions", "Ich bin traurig.", "Je suis triste."),
        ("Émotions", "Ich bin wütend.", "Je suis en colère."), ("Émotions", "Ich bin nervös.", "Je suis nerveux/nerveuse."),
        ("Émotions", "Ich freue mich.", "Je me réjouis."), ("Émotions", "Das ist toll!", "C'est génial !"),
        ("Émotions", "Das ist schrecklich.", "C'est terrible."),
        ("Téléphone", "Hallo, wer ist da?", "Allô, qui est à l'appareil ?"), ("Téléphone", "Kann ich mit Anna sprechen?", "Puis-je parler à Anna ?"),
        ("Téléphone", "Ich rufe später zurück.", "Je rappellerai plus tard."), ("Téléphone", "Schick mir eine Nachricht.", "Envoie-moi un message."),
        ("Téléphone", "Ich rufe dich morgen an.", "Je t'appelle demain."), ("Téléphone", "Kannst du mich zurückrufen?", "Peux-tu me rappeler ?"),
        ("Téléphone", "Die Verbindung ist schlecht.", "La connexion est mauvaise."), ("Téléphone", "Wie ist deine Nummer?", "Quel est ton numéro ?"),
        ("Internet", "Das Internet funktioniert nicht.", "Internet ne fonctionne pas."), ("Internet", "Mein Akku ist leer.", "Ma batterie est déchargée."),
        ("Internet", "Wo ist das WLAN?", "Où est le Wi-Fi ?"), ("Internet", "Ich habe kein Netz.", "Je n'ai pas de réseau."),
        ("Internet", "Ich schicke dir ein Foto.", "Je t'envoie une photo."), ("Internet", "Wie ist das Passwort?", "Quel est le mot de passe ?"),
        ("Internet", "Mein Handy ist kaputt.", "Mon téléphone est cassé."), ("Internet", "Ich lade mein Handy auf.", "Je recharge mon téléphone."),
        ("Invitations", "Hast du heute Zeit?", "As-tu le temps aujourd'hui ?"), ("Invitations", "Möchtest du mitkommen?", "Veux-tu venir avec moi ?"),
        ("Invitations", "Gern!", "Avec plaisir !"), ("Invitations", "Leider kann ich nicht.", "Malheureusement, je ne peux pas."),
        ("Invitations", "Lass uns ins Kino gehen.", "Allons au cinéma."), ("Invitations", "Hast du Lust auf einen Kaffee?", "As-tu envie d'un café ?"),
        ("Invitations", "Ich lade dich zum Essen ein.", "Je t'invite à manger."), ("Invitations", "Gute Idee!", "Bonne idée !"),
        ("Invitations", "Wann und wo treffen wir uns?", "Quand et où se retrouve-t-on ?"), ("Invitations", "Vielleicht ein andermal.", "Peut-être une autre fois."),
        ("Invitations", "Herzlichen Glückwunsch zum Geburtstag!", "Joyeux anniversaire !"),
        ("Politesse", "Danke!", "Merci !"), ("Politesse", "Vielen Dank!", "Merci beaucoup !"),
        ("Politesse", "Bitte schön.", "Je vous en prie."), ("Politesse", "Entschuldigung!", "Pardon ! / Excusez-moi !"),
        ("Politesse", "Es tut mir leid.", "Je suis désolé(e)."), ("Politesse", "Kein Problem.", "Pas de problème."),
        ("Politesse", "Bitte!", "S'il vous plaît ! / Je vous en prie !"), ("Politesse", "Entschuldigen Sie bitte.", "Excusez-moi, s'il vous plaît."),
        ("Politesse", "Darf ich?", "Puis-je ?"), ("Politesse", "Gesundheit!", "À vos souhaits !"),
        ("Politesse", "Viel Glück!", "Bonne chance !"), ("Politesse", "Alles Gute!", "Tous mes vœux !"),
        ("Politesse", "Gern geschehen.", "Avec plaisir. / De rien."),
        ("Opinions", "Das gefällt mir.", "Cela me plaît."), ("Opinions", "Ich mag Musik.", "J'aime la musique."),
        ("Opinions", "Das ist interessant.", "C'est intéressant."), ("Opinions", "Ich bin einverstanden.", "Je suis d'accord."),
        ("Opinions", "Das gefällt mir nicht.", "Cela ne me plaît pas."), ("Opinions", "Ich finde das gut.", "Je trouve ça bien."),
        ("Opinions", "Ich bin nicht einverstanden.", "Je ne suis pas d'accord."), ("Opinions", "Ich mag keinen Kaffee.", "Je n'aime pas le café."),
        ("Opinions", "Lieber Tee als Kaffee.", "Plutôt du thé que du café."), ("Opinions", "Das ist langweilig.", "C'est ennuyeux."),
        ("Opinions", "Das ist wichtig.", "C'est important."),
        ("Habitudes", "Ich stehe um sieben Uhr auf.", "Je me lève à sept heures."), ("Habitudes", "Ich frühstücke um acht Uhr.", "Je prends le petit-déjeuner à huit heures."),
        ("Habitudes", "Ich gehe zur Arbeit.", "Je vais au travail."), ("Habitudes", "Ich sehe fern.", "Je regarde la télévision."),
        ("Habitudes", "Ich lese ein Buch.", "Je lis un livre."), ("Habitudes", "Ich wache früh auf.", "Je me réveille tôt."),
        ("Habitudes", "Ich dusche jeden Morgen.", "Je me douche tous les matins."), ("Habitudes", "Ich putze mir die Zähne.", "Je me brosse les dents."),
        ("Habitudes", "Ich esse um zwölf Uhr zu Mittag.", "Je déjeune à midi."), ("Habitudes", "Ich komme um sechs Uhr nach Hause.", "Je rentre à la maison à dix-huit heures."),
        ("Habitudes", "Ich gehe um elf Uhr schlafen.", "Je vais dormir à vingt-trois heures."), ("Habitudes", "Am Samstag gehe ich einkaufen.", "Le samedi, je fais les courses."),
        ("Habitudes", "Ich mache jeden Tag Sport.", "Je fais du sport tous les jours."),
        ("Loisirs", "Was machst du gern?", "Qu'aimes-tu faire ?"), ("Loisirs", "Ich höre gern Musik.", "J'aime écouter de la musique."),
        ("Loisirs", "Ich spiele Fußball.", "Je joue au football."), ("Loisirs", "Ich lese gern.", "J'aime lire."),
        ("Loisirs", "Das macht Spaß.", "C'est amusant."), ("Loisirs", "Ich tanze gern.", "J'aime danser."),
        ("Loisirs", "Ich schwimme gern.", "J'aime nager."), ("Loisirs", "Ich koche gern.", "J'aime cuisiner."),
        ("Loisirs", "Ich gehe gern spazieren.", "J'aime me promener."), ("Loisirs", "Ich spiele Gitarre.", "Je joue de la guitare."),
        ("Loisirs", "Hast du ein Hobby?", "As-tu un passe-temps ?"),
        ("Vêtements", "Was soll ich anziehen?", "Que dois-je mettre ?"), ("Vêtements", "Das Hemd ist schön.", "La chemise est belle."),
        ("Vêtements", "Die Schuhe sind bequem.", "Les chaussures sont confortables."), ("Vêtements", "Das passt mir gut.", "Cela me va bien."),
        ("Hôtel", "Ich habe eine Reservierung.", "J'ai une réservation."), ("Hôtel", "Ich möchte ein Zimmer buchen.", "Je voudrais réserver une chambre."),
        ("Hôtel", "Wann ist das Frühstück?", "À quelle heure est le petit-déjeuner ?"), ("Hôtel", "Ich bleibe zwei Nächte.", "Je reste deux nuits."),
        ("Hôtel", "Ist das Frühstück inklusive?", "Le petit-déjeuner est-il inclus ?"), ("Hôtel", "Das Zimmer ist sehr sauber.", "La chambre est très propre."),
        ("Hôtel", "Wo ist der Aufzug?", "Où est l'ascenseur ?"), ("Hôtel", "Wann muss ich auschecken?", "Quand dois-je libérer la chambre ?"),
        ("Urgences", "Hilfe!", "Au secours !"), ("Urgences", "Rufen Sie die Polizei!", "Appelez la police !"),
        ("Urgences", "Ich brauche Hilfe.", "J'ai besoin d'aide."), ("Urgences", "Wo ist die nächste Apotheke?", "Où est la pharmacie la plus proche ?"),
        ("Urgences", "Es ist ein Notfall.", "C'est une urgence."), ("Urgences", "Rufen Sie einen Krankenwagen!", "Appelez une ambulance !"),
        ("Urgences", "Ich habe mich verlaufen.", "Je me suis perdu(e)."), ("Urgences", "Mein Portemonnaie ist weg.", "Mon portefeuille a disparu."),
        ("Urgences", "Vorsicht!", "Attention !"),
        ("Banque & poste", "Ich möchte Geld abheben.", "Je voudrais retirer de l'argent."), ("Banque & poste", "Wo ist der Geldautomat?", "Où est le distributeur ?"),
        ("Banque & poste", "Ich möchte ein Konto eröffnen.", "Je voudrais ouvrir un compte."), ("Banque & poste", "Ich möchte einen Brief schicken.", "Je voudrais envoyer une lettre."),
        ("Banque & poste", "Eine Briefmarke, bitte.", "Un timbre, s'il vous plaît."),
        ("Projets", "Was machen wir morgen?", "Que faisons-nous demain ?"), ("Projets", "Ich habe einen Plan.", "J'ai un plan."),
        ("Projets", "Ich werde dich anrufen.", "Je t'appellerai."), ("Projets", "Vielleicht morgen.", "Peut-être demain."),
        ("Projets", "Bis nächste Woche!", "À la semaine prochaine !"), ("Projets", "Ich möchte Deutsch lernen.", "Je voudrais apprendre l'allemand."),
        ("Projets", "Ich möchte in Berlin arbeiten.", "Je voudrais travailler à Berlin."), ("Projets", "Nächstes Jahr fahre ich nach Deutschland.", "L'année prochaine, je vais en Allemagne."),
        ("Projets", "Ich habe viele Pläne.", "J'ai beaucoup de projets.")
    ]
    for i, (cat, de, fr) in enumerate(data):
        cursor.execute(
            "INSERT INTO lessons(category,title,french,german,order_index) VALUES(?,?,?,?,?)",
            (cat, de, fr, de, i)
        )

def seed_vocab(cursor):
    vocab = [
        ("Personnes", "der Mann", "l'homme"), ("Personnes", "die Frau", "la femme"), ("Personnes", "das Kind", "l'enfant"),
        ("Personnes", "die Familie", "la famille"), ("Personnes", "der Vater", "le père"), ("Personnes", "die Mutter", "la mère"),
        ("Personnes", "der Sohn", "le fils"), ("Personnes", "die Tochter", "la fille"), ("Personnes", "der Bruder", "le frère"),
        ("Personnes", "die Schwester", "la sœur"), ("Personnes", "der Großvater", "le grand-père"), ("Personnes", "die Großmutter", "la grand-mère"),
        ("Personnes", "der Freund", "l'ami"), ("Personnes", "die Freundin", "l'amie"), ("Personnes", "der Nachbar", "le voisin"),
        ("Personnes", "die Nachbarin", "la voisine"), ("Personnes", "der Mensch", "l'être humain"), ("Personnes", "der Name", "le nom"),
        ("Personnes", "das Alter", "l'âge"), ("Personnes", "die Adresse", "l'adresse"),
        ("Maison", "das Haus", "la maison"), ("Maison", "die Wohnung", "l'appartement"), ("Maison", "das Zimmer", "la pièce / la chambre"),
        ("Maison", "die Küche", "la cuisine"), ("Maison", "das Bad", "la salle de bains"), ("Maison", "die Toilette", "les toilettes"),
        ("Maison", "der Flur", "le couloir"), ("Maison", "die Treppe", "l'escalier"), ("Maison", "die Tür", "la porte"),
        ("Maison", "das Fenster", "la fenêtre"), ("Maison", "die Wand", "le mur"), ("Maison", "der Boden", "le sol"),
        ("Maison", "die Decke", "le plafond / la couverture"), ("Maison", "das Dach", "le toit"), ("Maison", "der Schlüssel", "la clé"),
        ("Maison", "das Schloss", "la serrure / le château"), ("Maison", "der Garten", "le jardin"), ("Maison", "der Balkon", "le balcon"),
        ("Maison", "die Garage", "le garage"), ("Maison", "der Keller", "la cave"), ("Maison", "der Tisch", "la table"),
        ("Maison", "der Stuhl", "la chaise"), ("Maison", "das Sofa", "le canapé"), ("Maison", "der Sessel", "le fauteuil"),
        ("Maison", "das Bett", "le lit"), ("Maison", "der Schrank", "l'armoire"), ("Maison", "das Regal", "l'étagère"),
        ("Maison", "der Spiegel", "le miroir"), ("Maison", "die Lampe", "la lampe"), ("Maison", "der Teppich", "le tapis"),
        ("Maison", "der Vorhang", "le rideau"), ("Maison", "die Uhr", "l'horloge / la montre"), ("Maison", "das Bild", "l'image / le tableau"),
        ("Maison", "der Fernseher", "le téléviseur"), ("Maison", "das Radio", "la radio"), ("Maison", "der Computer", "l'ordinateur"),
        ("Maison", "der Laptop", "l'ordinateur portable"), ("Maison", "das Handy", "le téléphone portable"), ("Maison", "das Telefon", "le téléphone"),
        ("Maison", "das Ladegerät", "le chargeur"), ("Maison", "die Steckdose", "la prise électrique"), ("Maison", "der Lichtschalter", "l'interrupteur"),
        ("Maison", "der Kühlschrank", "le réfrigérateur"), ("Maison", "der Herd", "la cuisinière"), ("Maison", "der Ofen", "le four"),
        ("Maison", "die Mikrowelle", "le micro-ondes"), ("Maison", "die Spüle", "l'évier"), ("Maison", "der Teller", "l'assiette"),
        ("Maison", "die Tasse", "la tasse"), ("Maison", "das Glas", "le verre"), ("Maison", "die Flasche", "la bouteille"),
        ("Maison", "die Schüssel", "le bol / saladier"), ("Maison", "die Gabel", "la fourchette"), ("Maison", "das Messer", "le couteau"),
        ("Maison", "der Löffel", "la cuillère"), ("Maison", "der Topf", "la casserole"), ("Maison", "die Pfanne", "la poêle"),
        ("Maison", "der Deckel", "le couvercle"), ("Maison", "der Schwamm", "l'éponge"), ("Maison", "das Handtuch", "la serviette"),
        ("Maison", "die Seife", "le savon"), ("Maison", "die Zahnbürste", "la brosse à dents"), ("Maison", "die Zahnpasta", "le dentifrice"),
        ("Maison", "der Kamm", "le peigne"), ("Maison", "die Bürste", "la brosse"), ("Maison", "die Dusche", "la douche"),
        ("Maison", "die Badewanne", "la baignoire"), ("Maison", "das Waschbecken", "le lavabo"), ("Maison", "der Wasserhahn", "le robinet"),
        ("Maison", "die Waschmaschine", "la machine à laver"), ("Maison", "der Staubsauger", "l'aspirateur"), ("Maison", "der Besen", "le balai"),
        ("Maison", "der Eimer", "le seau"), ("Maison", "der Mülleimer", "la poubelle"), ("Maison", "das Bettlaken", "le drap"),
        ("Maison", "das Kissen", "l'oreiller"), ("Maison", "die Matratze", "le matelas"),
        ("Vêtements", "die Kleidung", "les vêtements"), ("Vêtements", "das Hemd", "la chemise"), ("Vêtements", "das T-Shirt", "le tee-shirt"),
        ("Vêtements", "die Hose", "le pantalon"), ("Vêtements", "der Rock", "la jupe"), ("Vêtements", "das Kleid", "la robe"),
        ("Vêtements", "die Jacke", "la veste"), ("Vêtements", "der Mantel", "le manteau"), ("Vêtements", "der Pullover", "le pull"),
        ("Vêtements", "der Schuh", "la chaussure"), ("Vêtements", "die Socke", "la chaussette"), ("Vêtements", "der Hut", "le chapeau"),
        ("Vêtements", "die Mütze", "le bonnet"), ("Vêtements", "der Gürtel", "la ceinture"), ("Vêtements", "die Tasche", "le sac"),
        ("Vêtements", "der Rucksack", "le sac à dos"), ("Vêtements", "der Regenschirm", "le parapluie"), ("Vêtements", "die Brille", "les lunettes"),
        ("Vêtements", "der Ring", "la bague"),
        ("Nourriture", "das Essen", "la nourriture / le repas"), ("Nourriture", "das Frühstück", "le petit-déjeuner"), ("Nourriture", "das Mittagessen", "le déjeuner"),
        ("Nourriture", "das Abendessen", "le dîner"), ("Nourriture", "das Brot", "le pain"), ("Nourriture", "das Brötchen", "le petit pain"),
        ("Nourriture", "die Butter", "le beurre"), ("Nourriture", "der Käse", "le fromage"), ("Nourriture", "das Ei", "l'œuf"),
        ("Nourriture", "die Milch", "le lait"), ("Nourriture", "der Joghurt", "le yaourt"), ("Nourriture", "der Reis", "le riz"),
        ("Nourriture", "die Nudeln", "les pâtes"), ("Nourriture", "die Kartoffel", "la pomme de terre"), ("Nourriture", "das Gemüse", "les légumes"),
        ("Nourriture", "das Obst", "les fruits"), ("Nourriture", "der Apfel", "la pomme"), ("Nourriture", "die Banane", "la banane"),
        ("Nourriture", "die Orange", "l'orange"), ("Nourriture", "die Zitrone", "le citron"), ("Nourriture", "die Traube", "le raisin"),
        ("Nourriture", "die Erdbeere", "la fraise"), ("Nourriture", "die Tomate", "la tomate"), ("Nourriture", "die Zwiebel", "l'oignon"),
        ("Nourriture", "die Karotte", "la carotte"), ("Nourriture", "der Salat", "la salade"), ("Nourriture", "die Gurke", "le concombre"),
        ("Nourriture", "der Fisch", "le poisson"), ("Nourriture", "das Fleisch", "la viande"), ("Nourriture", "das Hähnchen", "le poulet"),
        ("Nourriture", "die Wurst", "la saucisse"), ("Nourriture", "die Suppe", "la soupe"), ("Nourriture", "der Kuchen", "le gâteau"),
        ("Nourriture", "der Zucker", "le sucre"), ("Nourriture", "das Salz", "le sel"), ("Nourriture", "der Pfeffer", "le poivre"),
        ("Nourriture", "das Öl", "l'huile"), ("Nourriture", "das Wasser", "l'eau"), ("Nourriture", "der Kaffee", "le café"),
        ("Nourriture", "der Tee", "le thé"), ("Nourriture", "der Saft", "le jus"), ("Nourriture", "das Bier", "la bière"),
        ("Restaurant", "die Speisekarte", "le menu"), ("Restaurant", "die Rechnung", "l'addition / la facture"),
        ("Achats", "der Supermarkt", "le supermarché"), ("Achats", "der Laden", "le magasin"), ("Achats", "das Geschäft", "le commerce / magasin"),
        ("Achats", "der Markt", "le marché"), ("Achats", "der Preis", "le prix"), ("Achats", "das Geld", "l'argent"),
        ("Achats", "der Euro", "l'euro"), ("Achats", "die Münze", "la pièce de monnaie"), ("Achats", "der Geldschein", "le billet de banque"),
        ("Achats", "die Kasse", "la caisse"), ("Achats", "die Quittung", "le reçu"), ("Achats", "die Bank", "la banque"),
        ("Achats", "das Konto", "le compte"), ("Achats", "die Karte", "la carte"), ("Achats", "der Geldautomat", "le distributeur automatique"),
        ("Travail", "die Arbeit", "le travail"), ("Travail", "der Beruf", "la profession"), ("Travail", "das Büro", "le bureau"),
        ("Travail", "der Chef", "le chef / patron"), ("Travail", "die Chefin", "la cheffe / patronne"), ("Travail", "der Kollege", "le collègue"),
        ("Travail", "die Kollegin", "la collègue"), ("Travail", "der Kunde", "le client"), ("Travail", "die Kundin", "la cliente"),
        ("École", "der Lehrer", "l'enseignant"), ("École", "die Lehrerin", "l'enseignante"), ("École", "der Schüler", "l'élève"),
        ("École", "die Schülerin", "l'élève (fille)"), ("École", "der Student", "l'étudiant"), ("École", "die Studentin", "l'étudiante"),
        ("École", "die Schule", "l'école"), ("École", "die Universität", "l'université"), ("École", "der Kurs", "le cours"),
        ("École", "die Sprache", "la langue"), ("École", "das Wort", "le mot"), ("École", "der Satz", "la phrase"),
        ("École", "die Frage", "la question"), ("École", "die Antwort", "la réponse"), ("École", "das Buch", "le livre"),
        ("École", "das Heft", "le cahier"), ("École", "der Stift", "le stylo"), ("École", "der Bleistift", "le crayon"),
        ("École", "das Papier", "le papier"), ("École", "die Seite", "la page / le côté"), ("École", "die Aufgabe", "l'exercice / la tâche"),
        ("École", "die Prüfung", "l'examen"),
        ("Temps", "die Zeit", "le temps"), ("Temps", "der Tag", "le jour"), ("Temps", "die Woche", "la semaine"),
        ("Temps", "der Monat", "le mois"), ("Temps", "das Jahr", "l'année"), ("Temps", "der Morgen", "le matin"),
        ("Temps", "der Mittag", "midi"), ("Temps", "der Nachmittag", "l'après-midi"), ("Temps", "der Abend", "le soir"),
        ("Temps", "die Nacht", "la nuit"), ("Temps", "die Stunde", "l'heure"), ("Temps", "die Minute", "la minute"),
        ("Temps", "die Sekunde", "la seconde"),
        ("Jours", "der Montag", "lundi"), ("Jours", "der Dienstag", "mardi"), ("Jours", "der Mittwoch", "mercredi"),
        ("Jours", "der Donnerstag", "jeudi"), ("Jours", "der Freitag", "vendredi"), ("Jours", "der Samstag", "samedi"),
        ("Jours", "der Sonntag", "dimanche"),
        ("Saisons", "der Frühling", "le printemps"), ("Saisons", "der Sommer", "l'été"), ("Saisons", "der Herbst", "l'automne"),
        ("Saisons", "der Winter", "l'hiver"),
        ("Météo", "das Wetter", "le temps (météo)"), ("Météo", "die Sonne", "le soleil"), ("Météo", "der Regen", "la pluie"),
        ("Météo", "der Schnee", "la neige"), ("Météo", "der Wind", "le vent"), ("Météo", "die Wolke", "le nuage"),
        ("Météo", "der Himmel", "le ciel"), ("Météo", "die Temperatur", "la température"),
        ("Corps", "der Körper", "le corps"), ("Corps", "der Kopf", "la tête"), ("Corps", "das Haar", "le cheveu"),
        ("Corps", "das Gesicht", "le visage"), ("Corps", "das Auge", "l'œil"), ("Corps", "das Ohr", "l'oreille"),
        ("Corps", "die Nase", "le nez"), ("Corps", "der Mund", "la bouche"), ("Corps", "der Zahn", "la dent"),
        ("Corps", "der Hals", "le cou / la gorge"), ("Corps", "die Schulter", "l'épaule"), ("Corps", "der Arm", "le bras"),
        ("Corps", "die Hand", "la main"), ("Corps", "der Finger", "le doigt"), ("Corps", "der Bauch", "le ventre"),
        ("Corps", "der Rücken", "le dos"), ("Corps", "das Bein", "la jambe"), ("Corps", "das Knie", "le genou"),
        ("Corps", "der Fuß", "le pied"), ("Corps", "das Herz", "le cœur"),
        ("Santé", "der Arzt", "le médecin"), ("Santé", "die Ärztin", "la médecin"), ("Santé", "das Krankenhaus", "l'hôpital"),
        ("Santé", "die Apotheke", "la pharmacie"), ("Santé", "die Medizin", "le médicament / la médecine"), ("Santé", "der Schmerz", "la douleur"),
        ("Santé", "die Gesundheit", "la santé"), ("Santé", "die Krankheit", "la maladie"),
        ("Ville", "die Straße", "la rue"), ("Ville", "der Weg", "le chemin"), ("Ville", "der Platz", "la place"),
        ("Ville", "die Stadt", "la ville"), ("Ville", "das Dorf", "le village"), ("Ville", "das Land", "le pays / la campagne"),
        ("Transport", "der Bahnhof", "la gare"), ("Transport", "die Haltestelle", "l'arrêt"), ("Transport", "der Flughafen", "l'aéroport"),
        ("Transport", "der Zug", "le train"), ("Transport", "der Bus", "le bus"), ("Transport", "die Straßenbahn", "le tramway"),
        ("Transport", "die U-Bahn", "le métro"), ("Transport", "das Auto", "la voiture"), ("Transport", "das Fahrrad", "le vélo"),
        ("Transport", "das Motorrad", "la moto"), ("Transport", "das Taxi", "le taxi"), ("Transport", "das Flugzeug", "l'avion"),
        ("Transport", "das Ticket", "le billet"), ("Transport", "die Fahrkarte", "le titre de transport"), ("Transport", "der Fahrer", "le conducteur"),
        ("Transport", "die Fahrerin", "la conductrice"),
        ("Voyage", "die Reise", "le voyage"), ("Voyage", "der Urlaub", "les vacances"), ("Voyage", "das Hotel", "l'hôtel"),
        ("Voyage", "der Pass", "le passeport"), ("Voyage", "der Koffer", "la valise"), ("Voyage", "das Gepäck", "les bagages"),
        ("Urgences", "die Polizei", "la police"), ("Urgences", "die Feuerwehr", "les pompiers"), ("Urgences", "der Notfall", "l'urgence"),
        ("Urgences", "die Hilfe", "l'aide"),
        ("Concepts", "das Leben", "la vie"), ("Concepts", "die Liebe", "l'amour"), ("Concepts", "die Freude", "la joie"),
        ("Concepts", "das Glück", "la chance / le bonheur"), ("Concepts", "die Angst", "la peur"), ("Concepts", "die Idee", "l'idée"),
        ("Concepts", "das Problem", "le problème"), ("Concepts", "die Lösung", "la solution"), ("Concepts", "der Anfang", "le début"),
        ("Concepts", "das Ende", "la fin"), ("Concepts", "der Unterschied", "la différence"), ("Concepts", "die Möglichkeit", "la possibilité"),
        ("Concepts", "der Fehler", "l'erreur"), ("Concepts", "das Beispiel", "l'exemple"),
        ("Communication", "die Information", "l'information"), ("Communication", "die Nachricht", "le message / la nouvelle"), ("Communication", "der Brief", "la lettre"),
        ("Communication", "die E-Mail", "le courriel"), ("Communication", "das Foto", "la photo"),
        ("Verbes", "sein", "être"), ("Verbes", "haben", "avoir"), ("Verbes", "machen", "faire"),
        ("Verbes", "gehen", "aller"), ("Verbes", "kommen", "venir"), ("Verbes", "essen", "manger"),
        ("Verbes", "trinken", "boire"), ("Verbes", "schlafen", "dormir"), ("Verbes", "lernen", "apprendre"),
        ("Verbes", "lesen", "lire"), ("Verbes", "schreiben", "écrire"), ("Verbes", "sprechen", "parler"),
        ("Adjectifs", "groß", "grand"), ("Adjectifs", "klein", "petit"), ("Adjectifs", "alt", "vieux / âgé"),
        ("Adjectifs", "neu", "nouveau / neuf"), ("Adjectifs", "gut", "bon / bien"), ("Adjectifs", "schlecht", "mauvais"),
        ("Adjectifs", "schön", "beau"), ("Adjectifs", "heiß", "chaud (très chaud)"), ("Adjectifs", "kalt", "froid"),
        ("Mots utiles", "ja", "oui"), ("Mots utiles", "nein", "non"), ("Mots utiles", "vielleicht", "peut-être"),
        ("Mots utiles", "immer", "toujours"), ("Mots utiles", "nie", "jamais"), ("Mots utiles", "oft", "souvent"),
        ("Pronoms & questions", "ich", "je"), ("Pronoms & questions", "du", "tu"), ("Pronoms & questions", "er", "il"),
        ("Pronoms & questions", "sie", "elle / ils"), ("Pronoms & questions", "es", "il / cela"), ("Pronoms & questions", "wir", "nous"),
    ]
    for cat, de, fr in vocab:
        cursor.execute("INSERT INTO vocab(category, german, french) VALUES(?,?,?)", (cat, de, fr))

def seed_dialogues(cursor):
    dialogues = []
    base_dialogues = [
        ("Au supermarché", [
            ("A", "Entschuldigung, wo ist die Milch?", "Excusez-moi, où est le lait ?"),
            ("B", "Die Milch ist dort hinten.", "Le lait est là-bas au fond."),
            ("A", "Danke. Und wo ist das Brot?", "Merci. Et où est le pain ?"),
            ("B", "Das Brot ist neben der Kasse.", "Le pain est à côté de la caisse."),
            ("A", "Ich brauche auch Eier.", "J'ai aussi besoin d'œufs."),
            ("B", "Die Eier sind im Kühlregal.", "Les œufs sont dans le rayon frais."),
            ("A", "Wie viel kostet alles?", "Combien coûte tout ?"),
            ("B", "Das macht zehn Euro.", "Cela fait dix euros."),
            ("A", "Hier bitte. Danke!", "Voici, s'il vous plaît. Merci !"),
            ("B", "Danke, schönen Tag noch!", "Merci, bonne journée !")
        ]),
        ("Au restaurant", [
            ("A", "Guten Abend! Einen Tisch für zwei, bitte.", "Bonsoir ! Une table pour deux, s'il vous plaît."),
            ("B", "Natürlich, folgen Sie mir.", "Bien sûr, suivez-moi."),
            ("A", "Was empfehlen Sie heute?", "Que recommandez-vous aujourd'hui ?"),
            ("B", "Die Suppe ist sehr gut.", "La soupe est très bonne."),
            ("A", "Ich nehme die Suppe und ein Wasser.", "Je prends la soupe et une eau."),
            ("B", "Und Sie?", "Et vous ?"),
            ("A", "Ich möchte ein Schnitzel und ein Bier.", "Je voudrais un schnitzel et une bière."),
            ("B", "Sehr gerne. Etwas anderes?", "Avec plaisir. Autre chose ?"),
            ("A", "Nein, danke. Die Rechnung später, bitte.", "Non, merci. L'addition plus tard, s'il vous plaît."),
            ("B", "In Ordnung.", "D'accord.")
        ]),
        ("À la gare", [
            ("A", "Guten Tag, wann fährt der nächste Zug nach Berlin?", "Bonjour, quand part le prochain train pour Berlin ?"),
            ("B", "Um 14:30 Uhr, Gleis 3.", "À 14h30, voie 3."),
            ("A", "Wie lange dauert die Fahrt?", "Combien de temps dure le trajet ?"),
            ("B", "Etwa zwei Stunden.", "Environ deux heures."),
            ("A", "Ich möchte eine Fahrkarte kaufen.", "Je voudrais acheter un billet."),
            ("B", "Einfach oder hin und zurück?", "Aller simple ou aller-retour ?"),
            ("A", "Hin und zurück, bitte.", "Aller-retour, s'il vous plaît."),
            ("B", "Das kostet 40 Euro.", "Cela coûte 40 euros."),
            ("A", "Hier bitte. Danke!", "Voici. Merci !"),
            ("B", "Gute Reise!", "Bon voyage !")
        ]),
        ("Chez le médecin", [
            ("A", "Guten Tag, ich habe einen Termin.", "Bonjour, j'ai un rendez-vous."),
            ("B", "Ihr Name bitte?", "Votre nom, s'il vous plaît ?"),
            ("A", "Ich bin Thomas Müller.", "Je suis Thomas Müller."),
            ("B", "Nehmen Sie bitte Platz. Was fehlt Ihnen?", "Asseyez-vous, s'il vous plaît. Qu'avez-vous ?"),
            ("A", "Ich habe Halsschmerzen und Fieber.", "J'ai mal à la gorge et de la fièvre."),
            ("B", "Seit wann?", "Depuis quand ?"),
            ("A", "Seit zwei Tagen.", "Depuis deux jours."),
            ("B", "Sie brauchen Medikamente und Ruhe.", "Vous avez besoin de médicaments et de repos."),
            ("A", "Vielen Dank, Herr Doktor.", "Merci beaucoup, docteur."),
            ("B", "Gute Besserung!", "Bon rétablissement !")
        ]),
        ("À l'hôtel", [
            ("A", "Guten Abend, ich habe eine Reservierung.", "Bonsoir, j'ai une réservation."),
            ("B", "Wie ist Ihr Name?", "Quel est votre nom ?"),
            ("A", "Maria Schmidt.", "Maria Schmidt."),
            ("B", "Ja, ein Einzelzimmer für zwei Nächte.", "Oui, une chambre simple pour deux nuits."),
            ("A", "Ist das Frühstück inklusive?", "Le petit-déjeuner est-il inclus ?"),
            ("B", "Ja, von 7 bis 10 Uhr.", "Oui, de 7h à 10h."),
            ("A", "Wo ist der Aufzug?", "Où est l'ascenseur ?"),
            ("B", "Gleich links.", "Juste à gauche."),
            ("A", "Danke schön!", "Merci beaucoup !"),
            ("B", "Gute Nacht!", "Bonne nuit !")
        ]),
    ]
    
    for i in range(5, 50):
        dialogues.append((f"Dialogue quotidien {i}", [
            ("A", f"Guten Tag! Wie geht es dir heute am Tag {i}?", f"Bonjour ! Comment vas-tu aujourd'hui, jour {i} ?"),
            ("B", "Mir geht es gut, danke. Und dir?", "Je vais bien, merci. Et toi ?"),
            ("A", "Auch gut. Was machst du heute?", "Bien aussi. Que fais-tu aujourd'hui ?"),
            ("B", "Ich gehe zur Arbeit. Und du?", "Je vais au travail. Et toi ?"),
            ("A", "Ich lerne Deutsch.", "J'apprends l'allemand."),
            ("B", "Das ist sehr gut!", "C'est très bien !"),
            ("A", "Ich muss jetzt gehen.", "Je dois y aller maintenant."),
            ("B", "Wann sehen wir uns wieder?", "Quand nous reverrons-nous ?"),
            ("A", "Vielleicht am Wochenende.", "Peut-être ce week-end."),
            ("B", "Bis bald!", "À bientôt !")
        ]))
        
    for title, lines in base_dialogues + dialogues:
        lines_json = json.dumps([{"spk": s, "de": d, "fr": f} for s, d, f in lines])
        cursor.execute("INSERT INTO dialogues(title, lines_json) VALUES(?, ?)", (title, lines_json))

def seed_numbers(cursor):
    units = ["null", "eins", "zwei", "drei", "vier", "fünf", "sechs", "sieben", "acht", "neun"]
    teens = ["zehn", "elf", "zwölf", "dreizehn", "vierzehn", "fünfzehn", "sechzehn", "siebzehn", "achtzehn", "neunzehn"]
    tens = ["", "", "zwanzig", "dreißig", "vierzig", "fünfzig", "sechzig", "siebzig", "achtzig", "neunzig"]
    
    def num_to_de(n):
        if n < 10: return units[n]
        if n < 20: return teens[n-10]
        if n < 100:
            t = n // 10
            u = n % 10
            if u == 0: return tens[t]
            return units[u] + "und" + tens[t]
        if n == 100: return "hundert"
        if n < 1000:
            h = n // 100
            rest = n % 100
            prefix = units[h] + "hundert"
            if rest == 0: return prefix
            return prefix + num_to_de(rest)
        return "tausend"
    
    for i in range(0, 1001):
        de = num_to_de(i)
        fr = str(i)
        cursor.execute("INSERT INTO vocab(category, german, french) VALUES(?,?,?)", ("Nombres", de, fr))

# ---------------------------------------------------------
# DÉCORATEURS & SÉCURITÉ
# ---------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Veuillez vous connecter.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            flash("Accès réservé à l'administrateur.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper

def validate_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None

def validate_password(pwd):
    if len(pwd) < 8: return False
    if not re.search(r'[A-Z]', pwd): return False
    if not re.search(r'[a-z]', pwd): return False
    if not re.search(r'[0-9]', pwd): return False
    return True

# ---------------------------------------------------------
# HELPER VOCAL
# ---------------------------------------------------------
def say_btn(label, mode, fr="", de="", css="btn", style=""):
    style_attr = f' style="{h(style, quote=True)}"' if style else ""
    return (f'<button type="button" class="{css}" data-say="{mode}" '
            f'data-fr="{h(fr, quote=True)}" data-de="{h(de, quote=True)}"{style_attr}>{label}</button>')

def playlist_btn(label, kind, key, css="btn"):
    return (f'<button type="button" class="{css}" data-say="playlist" '
            f'data-kind="{h(kind, quote=True)}" data-key="{h(key, quote=True)}">{label}</button>')

# ---------------------------------------------------------
# FAVICON & STYLES & SCRIPTS (Correction Mobile/PC)
# ---------------------------------------------------------
FAVICON_SVG = """data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%2387CEEB'/><path d='M30 65V45c0-15 10-25 20-25s20 10 20 25v20' stroke='white' stroke-width='8' fill='none' stroke-linecap='round'/><rect x='25' y='60' width='12' height='20' rx='4' fill='white'/><rect x='63' y='60' width='12' height='20' rx='4' fill='white'/><text x='50' y='58' font-family='Arial' font-size='28' font-weight='bold' fill='white' text-anchor='middle'>N</text></svg>"""

BASE_CSS = """
<style>
:root{
  --sky:#87CEEB; --sky-dark:#4AA5D0; --sky-light:#E8F6FD;
  --ink:#0F2A3F; --muted:#5B7A90; --white:#FFFFFF;
  --ok:#2ECC71; --warn:#F39C12; --danger:#E74C3C;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,Arial,sans-serif;
     background:linear-gradient(180deg,#E8F6FD 0%,#F7FCFE 100%);
     color:var(--ink);min-height:100vh; padding-bottom: 90px; margin-left: 200px; transition: margin-left 0.3s;}
body.no-sidebar { margin-left: 0; }
.nav{background:var(--sky);color:white;padding:14px 22px;
     display:flex;justify-content:space-between;align-items:center;
     box-shadow:0 2px 8px rgba(0,0,0,.08);position:sticky;top:0;z-index:50; margin-left: -200px; transition: margin-left 0.3s;}
body.no-sidebar .nav { margin-left: 0; }
.nav .brand{font-weight:800;font-size:22px;letter-spacing:1px;display:flex;align-items:center;gap:10px}
.nav a{color:white;text-decoration:none;margin-left:16px;font-weight:500;opacity:.95}
.nav a:hover{opacity:1;text-decoration:underline}
.container{max-width:1100px;margin:0 auto;padding:24px 18px 60px}
.card{background:var(--white);border-radius:16px;padding:22px;
      box-shadow:0 6px 22px rgba(74,165,208,.12);margin-bottom:18px}
h1,h2,h3{color:var(--ink);margin-bottom:12px}
h1{font-size:26px}
h2{font-size:20px}
.btn{display:inline-block;padding:11px 20px;border-radius:10px;
     background:var(--sky-dark);color:white;text-decoration:none;
     border:none;cursor:pointer;font-weight:600;font-size:14px}
.btn:hover{background:#2F8CBB}
.btn.ghost{background:transparent;color:var(--sky-dark);border:2px solid var(--sky-dark)}
.btn.danger{background:var(--danger)}
.btn.ok{background:var(--ok)}
input,select,textarea{width:100%;padding:11px 13px;border:2px solid var(--sky-light);
     border-radius:10px;font-size:15px;margin:6px 0 14px;outline:none;
     transition:.2s;background:#fbfdff}
input:focus,select:focus,textarea:focus{border-color:var(--sky-dark)}
label{font-weight:600;font-size:14px;color:var(--muted)}
.flash{padding:12px 16px;border-radius:10px;margin-bottom:14px;font-weight:500}
.flash.success{background:#D4F5E3;color:#1E7A45}
.flash.danger{background:#FBE1DE;color:#A02A1B}
.flash.warning{background:#FFF1D6;color:#8A5C00}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px}
.lesson{background:white;border-radius:14px;padding:16px;
        box-shadow:0 4px 14px rgba(74,165,208,.10);
        border-left:5px solid var(--sky);transition:.2s;position:relative}
.lesson:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(74,165,208,.20)}
.lesson .cat{font-size:11px;text-transform:uppercase;color:var(--muted);letter-spacing:.6px}
.lesson .de{font-size:17px;font-weight:700;margin:6px 0}
.lesson .fr{font-size:14px;color:var(--muted)}
.lesson .actions{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}
.badge{display:inline-block;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:700}
.badge.done{background:#D4F5E3;color:#1E7A45}
.badge.todo{background:#FFF1D6;color:#8A5C00}
.player{background:linear-gradient(135deg,var(--sky-dark),#2F8CBB);
        color:white;border-radius:18px;padding:22px;margin-bottom:18px}
.player .fr{font-size:15px;opacity:.9;margin-bottom:6px}
.player .de{font-size:26px;font-weight:800;margin-bottom:16px}
.player .ctrl{display:flex;gap:10px;flex-wrap:wrap}
.player .ctrl button{background:rgba(255,255,255,.22);color:white;border:none;
        padding:11px 18px;border-radius:10px;font-weight:600;cursor:pointer;font-size:14px}
.player .ctrl button:hover{background:rgba(255,255,255,.35)}
.player .ctrl button.primary{background:white;color:var(--sky-dark)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #EAF3F8}
th{background:var(--sky-light);font-weight:700;color:var(--ink)}
.hero{background:linear-gradient(135deg,var(--sky),#B8E2F5);color:white;
      border-radius:22px;padding:40px 30px;text-align:center;margin-bottom:22px}
.hero h1{color:white;font-size:32px}
.hero p{opacity:.95;margin:10px 0 22px;font-size:16px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px}
.stat{background:white;border-radius:14px;padding:18px;text-align:center;
      box-shadow:0 4px 14px rgba(74,165,208,.10)}
.stat .num{font-size:28px;font-weight:800;color:var(--sky-dark)}
.stat .lbl{font-size:13px;color:var(--muted);margin-top:4px}
.quiz-opt{display:block;background:white;border:2px solid var(--sky-light);
      border-radius:10px;padding:13px 16px;margin:8px 0;cursor:pointer;transition:.15s}
.quiz-opt:hover{border-color:var(--sky-dark)}
.quiz-opt input{margin-right:10px;width:auto}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.tabs a{padding:8px 16px;border-radius:20px;background:white;text-decoration:none;
      font-size:13px;font-weight:600;color:var(--muted);border:2px solid var(--sky-light)}
.tabs a.active{background:var(--sky-dark);color:white;border-color:var(--sky-dark)}
footer{text-align:center;padding:24px;color:var(--muted);font-size:13px}
footer a { color: var(--muted); text-decoration: underline; margin: 0 10px;}

/* --- SIDEBAR (Niveaux) --- */
.sidebar {
  position: fixed; top: 0; left: 0; bottom: 0; width: 200px;
  background: #1a2a35; color: white; padding: 20px 15px; z-index: 60;
  display: flex; flex-direction: column; gap: 20px;
}
.sidebar h3 { color: #87CEEB; font-size: 14px; text-transform: uppercase; margin-bottom: 10px; letter-spacing: 1px;}
.sidebar .level { padding: 10px; border-radius: 8px; background: rgba(255,255,255,0.05); margin-bottom: 8px; cursor: not-allowed; opacity: 0.6;}
.sidebar .level .tag { font-size: 10px; background: #E74C3C; padding: 2px 6px; border-radius: 4px; float: right; font-weight: bold;}
.sidebar .level.active { background: #4AA5D0; opacity: 1; cursor: pointer;}
.sidebar .level.active .tag { display: none;}

@media (max-width: 800px) {
  body { margin-left: 0; }
  .nav { margin-left: 0; padding: 10px 15px; flex-direction: column; align-items: flex-start; gap: 10px;}
  .nav .brand { font-size: 18px; }
  .nav div:nth-child(2) { display: flex; flex-wrap: wrap; gap: 10px; margin-left: 0; }
  .nav a { margin-left: 0; font-size: 13px; }
  .sidebar { display: none; }
}

/* --- COOKIES BANNER --- */
#cookie-banner {
  position: fixed; bottom: 0; left: 0; right: 0;
  background: #1a2a35; color: white; padding: 15px 20px;
  display: flex; justify-content: space-between; align-items: center;
  z-index: 999; font-size: 14px; box-shadow: 0 -4px 10px rgba(0,0,0,0.2);
  transform: translateY(100%); transition: transform 0.3s;
}
#cookie-banner.show { transform: translateY(0); }
#cookie-banner button {
  background: #87CEEB; color: #0F2A3F; border: none; padding: 8px 16px;
  border-radius: 8px; font-weight: bold; cursor: pointer; margin-left: 10px;
}

/* --- LECTEUR GLOBAL (mode playlist) --- */
#global-player {
  position: fixed; bottom: 0; left: 0; right: 0;
  background: #1a2a35; color: white; padding: 12px 20px;
  display: none; justify-content: space-between; align-items: center; gap: 12px;
  box-shadow: 0 -4px 15px rgba(0,0,0,0.2); z-index: 100;
}
#global-player .info { font-weight: 600; font-size: 15px; min-width: 0; }
#global-player .info small { display: block; color: #87CEEB; font-size: 13px; font-weight: normal;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
#global-player .gp-ctrl { display: flex; gap: 8px; flex-shrink: 0; }
#global-player .gp-btn { background: rgba(255,255,255,.18); color: white; border: none;
  padding: 8px 14px; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 14px; }
#global-player .gp-btn:hover { background: rgba(255,255,255,.3); }
#global-player .gp-stop { background: var(--danger); }
#global-player .gp-stop:hover { background: #c0392b; }

/* --- NOTIFICATION VOCALE --- */
#voice-toast {
  position: fixed; left: 50%; bottom: 90px; transform: translateX(-50%) translateY(20px);
  background: #A02A1B; color: white; padding: 12px 18px; border-radius: 10px;
  font-size: 14px; font-weight: 500; max-width: 90%; text-align: center;
  opacity: 0; pointer-events: none; transition: .25s; z-index: 200;
}
#voice-toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

/* --- OEIL MOT DE PASSE --- */
.pwd-wrapper { position: relative; }
.pwd-wrapper input { padding-right: 40px; }
.pwd-toggle { position: absolute; right: 12px; top: 14px; cursor: pointer; font-size: 18px; color: var(--muted); }
.pwd-toggle:hover { color: var(--ink); }
</style>
"""

AUDIO_JS = r"""
(function () {
  'use strict';

  var synth = window.speechSynthesis;
  var supported = !!(synth && window.SpeechSynthesisUtterance);

  var voices = [];
  var pending = new Set();   
  var token = 0;             
  var warned = {};
  var list = [];             
  var idx = 0;
  var listTitle = '';
  var paused = false;
  var ttsFails = 0;          
  var curMode = 'tts';       
  var au = null;             
  var auResolve = null;
  var silCache = {};
  var mediaReady = false;

  var RATE_FR = 0.9;
  var RATE_DE = 0.75;
  var MP3_RATE_DE = 0.85;
  var GAP_FR_DE = 1200;      
  var GAP_NEXT = 2500;       

  var LS_ITEMS = 'natho_pl_items';
  var LS_IDX = 'natho_pl_idx';
  var LS_TITLE = 'natho_pl_title';
  var LS_TIME = 'natho_pl_time';

  var ALL_TITLES = {
    vocab: 'Tout le vocabulaire',
    lessons: 'Toutes les phrases',
    mix: 'Phrases + vocabulaire',
    dialogues: 'Tous les dialogues',
    numbers: 'Les nombres 0-1000'
  };

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function toast(msg) {
    var t = document.getElementById('voice-toast');
    if (!t) { alert(msg); return; }
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { t.classList.remove('show'); }, 6000);
  }

  function saveItems() {
    try {
      localStorage.setItem(LS_ITEMS, JSON.stringify(list));
      localStorage.setItem(LS_TITLE, listTitle);
      localStorage.setItem(LS_IDX, String(idx));
      localStorage.setItem(LS_TIME, String(Date.now()));
    } catch (e) {}
  }

  function saveIdx() {
    try {
      localStorage.setItem(LS_IDX, String(idx));
      localStorage.setItem(LS_TIME, String(Date.now()));
    } catch (e) {}
  }

  function clearState() {
    try {
      [LS_ITEMS, LS_IDX, LS_TITLE, LS_TIME].forEach(function (k) { localStorage.removeItem(k); });
    } catch (e) {}
  }

  function normLang(l) { return (l || '').replace('_', '-').toLowerCase(); }

  function refreshVoices() {
    if (!supported) return;
    var v = synth.getVoices();
    if (v && v.length) voices = v;
  }

  if (supported) {
    refreshVoices();
    if (synth.addEventListener) synth.addEventListener('voiceschanged', refreshVoices);
    else synth.onvoiceschanged = refreshVoices;
    var tries = 0;
    var poll = setInterval(function () {
      refreshVoices();
      tries++;
      if (voices.length || tries > 24) clearInterval(poll);
    }, 250);
  }

  function pickVoice(lang) {
    var prefix = normLang(lang).slice(0, 2);
    var all = voices.filter(function (v) { return normLang(v.lang).indexOf(prefix) === 0; });
    if (!all.length) return null;
    var exact = all.filter(function (v) { return normLang(v.lang) === normLang(lang); });
    var pool = exact.length ? exact : all;
    return pool.find(function (v) { return /google/i.test(v.name); }) ||
           pool.find(function (v) { return /natural|neural|online/i.test(v.name); }) ||
           pool[0];
  }

  function warnNoVoice(lang) {
    var key = lang.slice(0, 2);
    if (warned[key] || !voices.length) return;
    warned[key] = true;
    var nom = key === 'de' ? "allemande" : "française";
    toast("Aucune voix " + nom + " trouvée sur cet appareil.");
  }

  function ensure() {
    if (!supported) {
      toast("La synthèse vocale n'est pas supportée par ce navigateur.");
      return false;
    }
    return true;
  }

  function say(text, lang, rate) {
    return new Promise(function (resolve) {
      if (!text) { resolve(); return; }
      var u = new SpeechSynthesisUtterance(text);
      var v = pickVoice(lang);
      if (v) { u.voice = v; u.lang = v.lang.replace('_', '-'); }
      else { u.lang = lang; warnNoVoice(lang); }
      u.rate = rate;
      u.pitch = 1;
      u.volume = 1;

      var done = false;
      var timer = null;
      function finish() {
        if (done) return;
        done = true;
        clearTimeout(timer);
        pending.delete(u);
        resolve();
      }
      u.onend = finish;
      u.onerror = finish;
      timer = setTimeout(finish, 3000 + (text.length * 140) / rate);

      pending.add(u);
      try { synth.speak(u); } catch (e) { finish(); }
    });
  }

  function useMp3() { return window.NATHO_TTS === true && ttsFails < 2; }

  function getAudio() {
    if (!au) au = document.getElementById('natho-audio');
    if (!au) {
      au = document.createElement('audio');
      au.setAttribute('playsinline', '');
      document.body.appendChild(au);
    }
    return au;
  }

  function silenceUrl(ms) {
    if (silCache[ms]) return silCache[ms];
    var rate = 8000;
    var n = Math.floor(rate * ms / 1000);
    var buf = new ArrayBuffer(44 + n);
    var v = new DataView(buf);
    function ws(o, s) { for (var i = 0; i < s.length; i++) v.setUint8(o + i, s.charCodeAt(i)); }
    ws(0, 'RIFF'); v.setUint32(4, 36 + n, true); ws(8, 'WAVE'); ws(12, 'fmt ');
    v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true);
    v.setUint32(24, rate, true); v.setUint32(28, rate, true);
    v.setUint16(32, 1, true); v.setUint16(34, 8, true);
    ws(36, 'data'); v.setUint32(40, n, true);
    var u8 = new Uint8Array(buf);
    for (var i = 44; i < 44 + n; i++) u8[i] = 128;
    silCache[ms] = URL.createObjectURL(new Blob([buf], { type: 'audio/wav' }));
    return silCache[ms];
  }

  function playUrl(url, rate) {
    return new Promise(function (resolve) {
      var a = getAudio();
      var finished = false;
      var started = false;
      var wd = null;
      function cleanup() {
        clearTimeout(wd);
        a.removeEventListener('ended', onEnd);
        a.removeEventListener('error', onErr);
        a.removeEventListener('playing', onPlaying);
      }
      function done(ok) {
        if (finished) return;
        finished = true;
        cleanup();
        auResolve = null;
        resolve(ok);
      }
      function onEnd() { done(true); }
      function onErr() { done(false); }
      function onPlaying() { started = true; clearTimeout(wd); }

      auResolve = done;
      a.addEventListener('ended', onEnd);
      a.addEventListener('error', onErr);
      a.addEventListener('playing', onPlaying);
      wd = setTimeout(function () {
        if (!started) { try { a.pause(); } catch (e) {} done(false); }
      }, 20000);
      try {
        a.src = url;
        a.defaultPlaybackRate = rate;
        a.playbackRate = rate;
        var p = a.play();
        if (p && p.catch) p.catch(function () { done(false); });
      } catch (e) { done(false); }
    });
  }

  function auStop() {
    if (au) { try { au.pause(); } catch (e) {} }
    if (auResolve) { var r = auResolve; auResolve = null; r(false); }
    if ('mediaSession' in navigator) {
      try { navigator.mediaSession.playbackState = 'none'; } catch (e) {}
    }
  }

  async function seg(text, lang, my) {
    if (!text) return;
    if (useMp3()) {
      curMode = 'mp3';
      var url = '/tts?lang=' + lang + '&text=' + encodeURIComponent(text);
      var ok = await playUrl(url, lang === 'de' ? MP3_RATE_DE : 1);
      if (my !== token) return;
      if (ok) { ttsFails = 0; return; }
      ttsFails++;
    }
    if (my !== token) return;
    if (!supported) return;
    curMode = 'tts';
    await say(text, lang === 'de' ? 'de-DE' : 'fr-FR', lang === 'de' ? RATE_DE : RATE_FR);
  }

  async function gap(ms, my) {
    if (useMp3()) {
      curMode = 'mp3';
      var ok = await playUrl(silenceUrl(ms), 1);
      if (my !== token) return;
      if (ok) return;
    }
    if (my !== token) return;
    await sleep(ms);
  }

  function prefetch(from) {
    if (!useMp3()) return;
    for (var k = from; k < from + 2 && k < list.length; k++) {
      var it = list[k];
      try {
        fetch('/tts?lang=fr&text=' + encodeURIComponent(it.fr), { credentials: 'same-origin' }).catch(function () {});
        fetch('/tts?lang=de&text=' + encodeURIComponent(it.de), { credentials: 'same-origin' }).catch(function () {});
      } catch (e) {}
    }
  }

  function el(id) { return document.getElementById(id); }

  function hidePlayer() {
    var p = el('global-player');
    if (p) p.style.display = 'none';
  }

  function showPlayer(item) {
    var p = el('global-player');
    if (p) p.style.display = 'flex';
    var c = el('gp-count');
    if (c) c.textContent = (listTitle ? listTitle + ' · ' : '') + 'Lecture ' + (idx + 1) + ' / ' + list.length;
    var t = el('gp-text');
    if (t) t.textContent = item.de + '  —  ' + item.fr;
    var r = el('gp-resume');
    if (r) r.style.display = 'none';
    var b = el('gp-pause');
    if (b) { b.style.display = ''; b.textContent = paused ? '▶' : '⏸'; }
  }

  function showResumeBar(title, i, n) {
    var p = el('global-player');
    if (!p) return;
    p.style.display = 'flex';
    var c = el('gp-count');
    if (c) c.textContent = 'Playlist interrompue';
    var t = el('gp-text');
    if (t) t.textContent = (title ? title + ' — ' : '') + 'reprise à ' + (i + 1) + ' / ' + n;
    var r = el('gp-resume');
    if (r) r.style.display = '';
    var b = el('gp-pause');
    if (b) b.style.display = 'none';
  }

  function initMedia() {
    if (mediaReady || !('mediaSession' in navigator)) return;
    mediaReady = true;
    var ms = navigator.mediaSession;
    function setH(name, fn) { try { ms.setActionHandler(name, fn); } catch (e) {} }
    setH('play', function () { if (paused) togglePause(); });
    setH('pause', function () { if (!paused) togglePause(); });
    setH('previoustrack', function () { jump(-1); });
    setH('nexttrack', function () { jump(1); });
    setH('stop', function () { stopPlaylist(); });
  }

  function setMedia(item) {
    if (!('mediaSession' in navigator)) return;
    initMedia();
    try {
      navigator.mediaSession.metadata = new MediaMetadata({
        title: item.de,
        artist: item.fr,
        album: 'NATHO · Deutsch A1'
      });
      navigator.mediaSession.playbackState = paused ? 'paused' : 'playing';
    } catch (e) {}
  }

  function togglePause() {
    if (!list.length) return;
    if (!paused) {
      if (curMode === 'mp3' && au) { try { au.pause(); } catch (e) {} }
      else if (supported) { try { synth.pause(); } catch (e) {} }
      paused = true;
    } else {
      if (curMode === 'mp3' && au) {
        var p = au.play();
        if (p && p.catch) p.catch(function () {});
      } else if (supported) { try { synth.resume(); } catch (e) {} }
      paused = false;
    }
    try { navigator.mediaSession.playbackState = paused ? 'paused' : 'playing'; } catch (e) {}
    var b = el('gp-pause');
    if (b) b.textContent = paused ? '▶' : '⏸';
  }

  async function begin() {
    var busy = supported && (synth.speaking || synth.pending);
    token++;
    list = [];
    idx = 0;
    listTitle = '';
    paused = false;
    hidePlayer();
    clearState();
    auStop();
    if (supported) {
      if (synth.paused) synth.resume();
      synth.cancel();
    }
    pending.clear();
    if (busy) await sleep(120);
    return token;
  }

  async function speak(text, lang) {
    if (!ensure()) return;
    lang = lang || 'de-DE';
    var my = await begin();
    if (my !== token) return;
    curMode = 'tts';
    await say(text, lang, lang.indexOf('de') === 0 ? RATE_DE : RATE_FR);
  }

  async function speakPair(fr, de) {
    if (!ensure()) return;
    var my = await begin();
    if (my !== token) return;
    curMode = 'tts';
    await say(fr, 'fr-FR', RATE_FR);
    if (my !== token) return;
    await sleep(GAP_FR_DE);
    if (my !== token) return;
    await say(de, 'de-DE', RATE_DE);
  }

  async function loop(my) {
    while (my === token && idx < list.length) {
      var it = list[idx];
      saveIdx();
      showPlayer(it);
      setMedia(it);
      prefetch(idx + 1);
      await seg(it.fr, 'fr', my);
      if (my !== token) return;
      await gap(GAP_FR_DE, my);
      if (my !== token) return;
      await seg(it.de, 'de', my);
      if (my !== token) return;
      await gap(GAP_NEXT, my);
      if (my !== token) return;
      idx++;
    }
    if (my === token) stopPlaylist();
  }

  async function startPlaylist(items, title) {
    if (!useMp3() && !ensure()) return;
    if (!items || !items.length) { toast("La playlist est vide."); return; }
    ttsFails = 0;
    var my = await begin();
    if (my !== token) return;
    list = items;
    idx = 0;
    listTitle = title || '';
    saveItems();
    loop(my);
  }

  function flat(kind) {
    var d = window.NATHO_PLAYLISTS || {};
    var src = d[kind] || {};
    var cats = (d.order && d.order[kind]) || Object.keys(src);
    var r = [];
    cats.forEach(function (c) { if (src[c]) r = r.concat(src[c]); });
    return r;
  }

  function getItems(kind, key) {
    var d = window.NATHO_PLAYLISTS || {};
    if (kind === 'all') {
      if (key === 'vocab') return flat('vocab');
      if (key === 'lessons') return flat('lessons');
      if (key === 'mix') return flat('lessons').concat(flat('vocab'));
      if (key === 'dialogues') return flat('dialogues');
      if (key === 'numbers') return flat('numbers');
      return null;
    }
    return d[kind] && d[kind][key];
  }

  function startPlaylistByKey(kind, key) {
    var title = kind === 'all' ? (ALL_TITLES[key] || key) : key;
    startPlaylist(getItems(kind, key), title);
  }

  async function resumePlaylist() {
    var items = [];
    var i = 0;
    var title = '';
    try {
      items = JSON.parse(localStorage.getItem(LS_ITEMS) || '[]');
      i = parseInt(localStorage.getItem(LS_IDX) || '0', 10) || 0;
      title = localStorage.getItem(LS_TITLE) || '';
    } catch (e) { return; }
    if (!items.length) return;
    if (!useMp3() && !ensure()) return;
    ttsFails = 0;
    var my = await begin();
    if (my !== token) return;
    list = items;
    idx = Math.min(i, items.length - 1);
    listTitle = title;
    saveItems();
    loop(my);
  }

  function stopPlaylist() {
    token++;
    list = [];
    idx = 0;
    listTitle = '';
    paused = false;
    auStop();
    if (supported) {
      if (synth.paused) synth.resume();
      synth.cancel();
    }
    pending.clear();
    hidePlayer();
    clearState();
  }

  async function jump(delta) {
    if (!list.length) return;
    var n = idx + delta;
    if (n < 0) n = 0;
    if (n >= list.length) { stopPlaylist(); return; }
    var busy = supported && (synth.speaking || synth.pending);
    token++;
    var my = token;
    idx = n;
    paused = false;
    auStop();
    if (supported) {
      if (synth.paused) synth.resume();
      synth.cancel();
    }
    pending.clear();
    if (busy) await sleep(120);
    if (my !== token) return;
    loop(my);
  }

  function initResume() {
    try {
      var raw = localStorage.getItem(LS_ITEMS);
      if (!raw) return;
      var t = parseInt(localStorage.getItem(LS_TIME) || '0', 10);
      if (!t || Date.now() - t > 86400000) { clearState(); return; }
      var items = JSON.parse(raw);
      var i = parseInt(localStorage.getItem(LS_IDX) || '0', 10) || 0;
      if (!items.length || i >= items.length) { clearState(); return; }
      showResumeBar(localStorage.getItem(LS_TITLE) || '', i, items.length);
    } catch (e) {}
  }

  function runScripts(root) {
    root.querySelectorAll('script').forEach(function (old) {
      var s = document.createElement('script');
      if (old.src) s.src = old.src; else s.text = old.textContent;
      old.parentNode.replaceChild(s, old);
    });
  }

  async function go(url, opts, push) {
    try {
      var res = await fetch(url, opts || { credentials: 'same-origin', cache: 'no-cache' });
      var ct = res.headers.get('content-type') || '';
      if (ct.indexOf('text/html') < 0) { window.location.href = url; return; }
      var html = await res.text();
      var doc = new DOMParser().parseFromString(html, 'text/html');
      var newC = doc.querySelector('.container');
      var oldC = document.querySelector('.container');
      if (!newC || !oldC) { window.location.href = res.url || url; return; }
      var newN = doc.querySelector('.nav');
      var oldN = document.querySelector('.nav');
      if (newN && oldN) oldN.innerHTML = newN.innerHTML;
      oldC.innerHTML = newC.innerHTML;
      document.title = doc.title;
      if (push) history.pushState({}, '', res.url || url);
      runScripts(oldC);
      window.scrollTo(0, 0);
    } catch (err) {
      window.location.href = url;
    }
  }

  function shouldNav(a, e) {
    if (!a || !a.href) return false;
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return false;
    if (a.target && a.target !== '_self') return false;
    if (a.hasAttribute('download')) return false;
    if (a.origin !== window.location.origin) return false;
    if (a.pathname === window.location.pathname && a.search === window.location.search && a.hash) return false;
    return true;
  }

  document.addEventListener('click', function (e) {
    var t = e.target;
    var b = t && t.closest ? t.closest('[data-say]') : null;
    if (b) {
      e.preventDefault();
      var mode = b.getAttribute('data-say');
      var fr = b.getAttribute('data-fr') || '';
      var de = b.getAttribute('data-de') || '';
      if (mode === 'pair') speakPair(fr, de);
      else if (mode === 'de') speak(de, 'de-DE');
      else if (mode === 'fr') speak(fr, 'fr-FR');
      else if (mode === 'playlist') startPlaylistByKey(b.getAttribute('data-kind'), b.getAttribute('data-key'));
      return;
    }
    var a = t && t.closest ? t.closest('a[href]') : null;
    if (a && shouldNav(a, e)) {
      e.preventDefault();
      if (a.pathname === '/logout') stopPlaylist();
      go(a.href, { credentials: 'same-origin', cache: 'no-cache' }, true);
    }
  });

  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (!f || f.tagName !== 'FORM' || e.defaultPrevented) return;
    var method = (f.getAttribute('method') || 'get').toLowerCase();
    if (method !== 'post') return;
    e.preventDefault();
    go(f.action || window.location.href, { method: 'POST', body: new FormData(f), credentials: 'same-origin' }, true);
  });

  window.addEventListener('popstate', function () {
    go(window.location.href, { credentials: 'same-origin', cache: 'no-cache' }, false);
  });

  initResume();

  window.NathoAudio = {
    speak: speak,
    speakPair: speakPair,
    startPlaylist: startPlaylist,
    startPlaylistByKey: startPlaylistByKey,
    stopPlaylist: stopPlaylist,
    resume: resumePlaylist,
    togglePause: togglePause,
    prev: function () { jump(-1); },
    next: function () { jump(1); }
  };
  window.speak = speak;
  window.speakPair = speakPair;
  window.startPlaylist = startPlaylist;
  window.stopPlaylist = stopPlaylist;
})();
"""

def layout(title, body, user=None):
    show_sidebar = bool(user)
    
    nav_links = ""
    if user:
        nav_links = f"""
            <a href="{url_for('dashboard')}">Cours</a>
            <a href="{url_for('vocabulaire')}">Vocabulaire 📖</a>
            <a href="{url_for('dialogues')}">Dialogues 🗣️</a>
            <a href="{url_for('playlists')}">Playlists 🎵</a>
            <a href="{url_for('goethe')}">Examen Goethe</a>
            <a href="{url_for('progress')}">Progrès</a>
            {"<a href='"+url_for('admin')+"'>Admin</a>" if user['is_admin'] else ""}
            <a href="{url_for('logout')}">Déconnexion</a>
        """
    else:
        nav_links = f"""<a href="{url_for('login')}">Connexion</a>
                        <a href="{url_for('register')}">Inscription</a>"""
                        
    sidebar_html = ""
    if show_sidebar:
        sidebar_html = """
        <div class="sidebar">
            <h3>Niveaux</h3>
            <div class="level active">
                <strong>A1</strong> <span style="font-size:11px;display:block;">Actuel</span>
            </div>
            <div class="level">
                <strong>A2</strong> <span class="tag">Bientôt</span>
                <span style="font-size:11px;display:block;margin-top:4px;">Élémentaire</span>
            </div>
            <div class="level">
                <strong>B1</strong> <span class="tag">Bientôt</span>
                <span style="font-size:11px;display:block;margin-top:4px;">Intermédiaire</span>
            </div>
            <div class="level">
                <strong>B2</strong> <span class="tag">Bientôt</span>
                <span style="font-size:11px;display:block;margin-top:4px;">Avancé</span>
            </div>
            <div style="margin-top:auto; font-size:11px; color:#5B7A90; text-align:center;">
                © NATHO 2026
            </div>
        </div>
        """
        
    body_class = "" if show_sidebar else "no-sidebar"

    return f"""
<!doctype html><html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NATHO — {title}</title>
<link rel="icon" type="image/svg+xml" href="{FAVICON_SVG}">
{BASE_CSS}
</head><body class="{body_class}">

{sidebar_html}

<div class="nav">
  <div class="brand"><img src="{FAVICON_SVG}" width="28" height="28" style="border-radius:6px;"> NATHO · Deutsch A1</div>
  <div>{nav_links}</div>
</div>
<div class="container">
  {''.join(f'<div class="flash {k}">{m}</div>' for k,m in get_flashed_messages(with_categories=True))}
  {body}
</div>

<!-- COOKIES BANNER -->
<div id="cookie-banner">
    <div>🍪 Nous utilisons des cookies pour améliorer votre expérience sur NATHO. En continuant, vous acceptez notre <a href="/politique" style="color:#87CEEB">Politique de confidentialité</a>.</div>
    <button onclick="acceptCookies()">J'accepte</button>
</div>
<script>
    if (!localStorage.getItem('natho_cookies_accepted')) {{
        setTimeout(function() {{ document.getElementById('cookie-banner').classList.add('show'); }}, 1500);
    }}
    function acceptCookies() {{
        localStorage.setItem('natho_cookies_accepted', 'true');
        document.getElementById('cookie-banner').classList.remove('show');
    }}
</script>

<!-- LECTEUR GLOBAL (SPOTIFY MODE) -->
<div id="global-player">
  <div class="info"><span id="gp-count">En cours de lecture...</span><small id="gp-text">En attente</small></div>
  <div class="gp-ctrl">
    <button type="button" class="gp-btn" id="gp-resume" style="display:none" onclick="NathoAudio.resume()">▶ Reprendre</button>
    <button type="button" class="gp-btn" onclick="NathoAudio.prev()" title="Précédent">⏮</button>
    <button type="button" class="gp-btn" id="gp-pause" onclick="NathoAudio.togglePause()" title="Pause / Lecture">⏸</button>
    <button type="button" class="gp-btn" onclick="NathoAudio.next()" title="Suivant">⏭</button>
    <button type="button" class="gp-btn gp-stop" onclick="NathoAudio.stopPlaylist()">⏹ Arrêter</button>
  </div>
</div>
<div id="voice-toast"></div>
<audio id="natho-audio" preload="auto" playsinline></audio>

<footer>
    © NATHO — Plateforme d'apprentissage de l'allemand A1 · Prototype v3.5<br>
    <a href="/politique">Politique de confidentialité</a> | 
    <a href="/cgu">Conditions d'utilisation</a> | 
    <a href="/mentions">Mentions légales</a>
</footer>
<script>window.NATHO_TTS = {'true' if TTS_OK else 'false'};</script>
<script>{{% raw %}}{AUDIO_JS}{{% endraw %}}</script>
</body></html>"""

# ---------------------------------------------------------
# VOIX SERVEUR (MP3)
# ---------------------------------------------------------
TTS_DIR = "/app/data/tts_cache"
try:
    os.makedirs(TTS_DIR, exist_ok=True)
    os.chmod(TTS_DIR, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
except Exception as e:
    print("Attention, impossible de créer le dossier audio :", e)

@app.route("/tts")
@login_required
def tts():
    if not TTS_OK:
        return ("", 404)
    text = request.args.get("text", "").strip()[:300]
    lang = request.args.get("lang", "de")
    if lang not in ("de", "fr") or not text:
        return ("", 400)
    key = hashlib.sha1((lang + "|" + text).encode("utf-8")).hexdigest()
    path = os.path.join(TTS_DIR, key + ".mp3")
    if not os.path.exists(path):
        try:
            tmp = path + "." + secrets.token_hex(4) + ".tmp"
            gTTS(text=text, lang=lang).save(tmp)
            os.replace(tmp, path)
        except Exception:
            return ("", 502)
    return send_file(path, mimetype="audio/mpeg", conditional=True, max_age=604800)

# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------
@app.route("/")
def index():
    user = None
    if "user_id" in session:
        user = {"is_admin": session.get("is_admin")}
    body = """
    <div class="hero">
        <h1>Bienvenue sur NATHO</h1>
        <p>Apprends l'allemand A1 comme sur Spotify : écoute, répète, progresse.</p>
        <a href="/register" class="btn">Commencer gratuitement</a>
        <a href="/login" class="btn ghost" style="background:white;color:#2F8CBB">Se connecter</a>
    </div>
    <div class="grid">
        <div class="card"><h3>🎧 Mode Audio</h3><p>Le français puis l'allemand, lu à voix haute. Idéal pour mémoriser.</p></div>
        <div class="card"><h3>📚 Bibliothèque A1</h3><p>300 expressions et 320 mots issus du programme Goethe A1.</p></div>
        <div class="card"><h3>📝 Examen Goethe A1</h3><p>Hören, Lesen, Schreiben, Sprechen : un vrai simulateur d'examen.</p></div>
        <div class="card"><h3>📈 Suivi personnel</h3><p>Ton compte, tes progrès, tes résultats, à tout moment.</p></div>
    </div>
    """
    return render_template_string(layout("Accueil", body, user))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        pwd = request.form.get("password","")
        
        if not name or not email or not pwd:
            flash("Tous les champs sont requis.","danger"); return redirect(url_for("register"))
        
        if not validate_email(email):
            flash("Format d'email invalide. Exemple : nom@domaine.com","danger"); return redirect(url_for("register"))
        
        if not validate_password(pwd):
            flash("Mot de passe trop faible. Il faut au moins 8 caractères, une majuscule, une minuscule et un chiffre.","danger"); return redirect(url_for("register"))
        
        db = get_db()
        try:
            db.execute("INSERT INTO users(name,email,password) VALUES(?,?,?)",
                       (name,email,hash_pwd(pwd)))
            db.commit()
            flash("Compte créé ! Connecte-toi.","success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Cet email est déjà utilisé.","danger")
            return redirect(url_for("register"))
    body = """
    <h1>Créer un compte</h1>
    <div class="card">
      <form method="post" onsubmit="return checkForm()">
        <label>Nom complet</label><input name="name" required>
        <label>Email</label><input name="email" type="email" required placeholder="exemple@domaine.com">
        
        <label>Mot de passe</label>
        <div class="pwd-wrapper">
            <input name="password" id="pwd" type="password" required placeholder="Min. 8 car., Maj., min., chiffre">
            <span class="pwd-toggle" onclick="togglePwd()">👁</span>
        </div>
        <div id="pwd-strength" style="font-size:12px; margin-top:-10px; margin-bottom:12px; color:#5B7A90;"></div>
        
        <button class="btn" type="submit">S'inscrire</button>
      </form>
      <p style="margin-top:12px;color:#5B7A90">Déjà inscrit ? <a href="/login">Connexion</a></p>
    </div>
    <script>
        function togglePwd() {
            var x = document.getElementById("pwd");
            if (x.type === "password") x.type = "text";
            else x.type = "password";
        }
        document.getElementById("pwd").addEventListener("input", function() {
            var p = this.value;
            var str = 0;
            if (p.length >= 8) str++;
            if (/[A-Z]/.test(p)) str++;
            if (/[a-z]/.test(p)) str++;
            if (/[0-9]/.test(p)) str++;
            var el = document.getElementById("pwd-strength");
            if (p.length === 0) { el.innerHTML = ""; return; }
            if (str <= 2) { el.innerHTML = "🔴 Faible"; el.style.color = "#E74C3C"; }
            else if (str === 3) { el.innerHTML = "🟠 Moyen"; el.style.color = "#F39C12"; }
            else { el.innerHTML = "🟢 Fort"; el.style.color = "#2ECC71"; }
        });
        function checkForm() {
            var p = document.getElementById("pwd").value;
            var ok = p.length >= 8 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p);
            if (!ok) { alert("Le mot de passe ne respecte pas les critères de sécurité."); return false; }
            return true;
        }
    </script>
    """
    return render_template_string(layout("Inscription", body))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pwd = request.form.get("password","")
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        
        if row and row["password"] == hash_pwd(pwd):
            session.clear()
            session["user_id"] = row["id"]
            session["user_name"] = row["name"]
            session["is_admin"] = bool(row["is_admin"])
            flash(f"Bienvenue {row['name']} !","success")
            return redirect(url_for("admin") if row["is_admin"] else url_for("dashboard"))
        
        flash("Email ou mot de passe incorrect.","danger")
    body = """
    <h1>Connexion</h1>
    <div class="card">
      <form method="post">
        <label>Email</label><input name="email" type="email" required>
        <label>Mot de passe</label><input name="password" type="password" required>
        <button class="btn" type="submit">Se connecter</button>
      </form>
      <p style="margin-top:12px;color:#5B7A90">Pas de compte ? <a href="/register">Inscription</a></p>
    </div>
    """
    return render_template_string(layout("Connexion", body))

@app.route("/logout")
def logout():
    session.clear()
    flash("Tu es déconnecté.","success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    cats = db.execute("SELECT DISTINCT category FROM lessons ORDER BY category").fetchall()
    cat = request.args.get("cat","")
    q = "SELECT * FROM lessons"
    params = []
    if cat:
        q += " WHERE category=?"; params.append(cat)
    q += " ORDER BY order_index"
    lessons = db.execute(q, params).fetchall()

    prog = {r["lesson_id"]: r for r in db.execute(
        "SELECT * FROM progress WHERE user_id=?", (session["user_id"],)).fetchall()}
    completed = sum(1 for r in prog.values() if r["completed"])
    total = db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
    pct = int(100*completed/total) if total else 0

    tabs = f'<a href="{url_for("dashboard")}" class="{"active" if not cat else ""}">Tout</a>'
    for c in cats:
        tabs += f'<a href="{url_for("dashboard", cat=c["category"])}" class="{"active" if cat==c["category"] else ""}">{c["category"]}</a>'

    cards = ""
    for l in lessons:
        st = prog.get(l["id"])
        badge = ""
        if st and st["completed"]:
            badge = '<span class="badge done">✔ Terminé</span>'
        elif st and st["listened"]:
            badge = '<span class="badge todo">⏯ En cours</span>'
        cards += f"""
        <div class="lesson">
          <div class="cat">{l['category']}</div>
          <div class="de">{l['german']}</div>
          <div class="fr">{l['french']}</div>
          <div class="actions">
            {say_btn("▶ Écouter", "pair", l['french'], l['german'])}
            {say_btn("🔊 Allemand", "de", l['french'], l['german'], css="btn ghost")}
            {badge}
          </div>
        </div>"""

    intro_btn = say_btn("▶ Lire la phrase", "pair", "Prêt ? Allons-y !", "Bereit? Los geht's!", css="primary")

    body = f"""
    <div class="player">
      <div class="fr">Mode audio · apprends en écoutant</div>
      <div class="de">Bereit? Los geht's! 🎧</div>
      <div class="ctrl">
        {intro_btn}
      </div>
    </div>
    <div class="stat-grid" style="margin-bottom:18px">
      <div class="stat"><div class="num">{completed}</div><div class="lbl">Leçons terminées</div></div>
      <div class="stat"><div class="num">{total}</div><div class="lbl">Leçons totales</div></div>
      <div class="stat"><div class="num">{pct}%</div><div class="lbl">Progression</div></div>
    </div>
    <div class="tabs">{tabs}</div>
    <div class="grid">{cards}</div>
    """
    return render_template_string(layout("Cours", body, {"is_admin": session.get("is_admin")}))

@app.route("/lesson/<int:lid>", methods=["GET","POST"])
@login_required
def lesson(lid):
    db = get_db()
    l = db.execute("SELECT * FROM lessons WHERE id=?", (lid,)).fetchone()
    if not l:
        flash("Leçon introuvable.","danger"); return redirect(url_for("dashboard"))
    if request.method == "POST":
        done = request.form.get("done") == "1"
        db.execute("""INSERT INTO progress(user_id,lesson_id,listened,completed)
                      VALUES(?,?,1,?)
                      ON CONFLICT(user_id,lesson_id) DO UPDATE SET
                      listened=1, completed=MAX(completed,excluded.completed),
                      updated_at=CURRENT_TIMESTAMP""",
                   (session["user_id"], lid, 1 if done else 0))
        db.commit()
        flash("Progression enregistrée.","success")
        return redirect(url_for("dashboard"))
    body = f"""
    <div class="player">
      <div class="fr">{l['french']}</div>
      <div class="de">{l['german']}</div>
      <div class="ctrl">
        {say_btn("▶ FR puis DE (lent)", "pair", l['french'], l['german'], css="primary")}
        {say_btn("🔊 Allemand seul", "de", l['french'], l['german'], css="")}
        {say_btn("🇫🇷 Français seul", "fr", l['french'], l['german'], css="")}
      </div>
    </div>
    <div class="card">
      <form method="post">
        <input type="hidden" name="done" value="1">
        <button class="btn ok" type="submit">✔ Marquer comme terminé</button>
      </form>
    </div>
    <a href="/dashboard" class="btn ghost">← Retour aux cours</a>
    """
    return render_template_string(layout(l['german'], body, {"is_admin": session.get("is_admin")}))

@app.route("/vocabulaire")
@login_required
def vocabulaire():
    db = get_db()
    cats = db.execute("SELECT DISTINCT category FROM vocab ORDER BY category").fetchall()
    cat = request.args.get("cat","")
    q = "SELECT * FROM vocab"
    params = []
    if cat:
        q += " WHERE category=?"; params.append(cat)
    q += " ORDER BY id"
    words = db.execute(q, params).fetchall()

    tabs = f'<a href="{url_for("vocabulaire")}" class="{"active" if not cat else ""}">Tout</a>'
    for c in cats:
        tabs += f'<a href="{url_for("vocabulaire", cat=c["category"])}" class="{"active" if cat==c["category"] else ""}">{c["category"]}</a>'

    cards = ""
    for w in words:
        cards += f"""
        <div class="lesson">
          <div class="cat">{w['category']}</div>
          <div class="de">{w['german']}</div>
          <div class="fr">{w['french']}</div>
          <div class="actions">
            {say_btn("▶ Écouter", "pair", w['french'], w['german'])}
            {say_btn("🔊 Allemand", "de", w['french'], w['german'], css="btn ghost")}
          </div>
        </div>"""

    body = f"""
    <h1>Bibliothèque de Vocabulaire 📖</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">Plus de 320 mots allemands avec leur article (der, die, das) + Les nombres de 0 à 1000.</p>
    <div class="tabs">{tabs}</div>
    <div class="grid">{cards}</div>
    """
    return render_template_string(layout("Vocabulaire", body, {"is_admin": session.get("is_admin")}))

@app.route("/dialogues")
@login_required
def dialogues():
    db = get_db()
    rows = db.execute("SELECT * FROM dialogues").fetchall()
    
    cards = ""
    for r in rows:
        lines = json.loads(r["lines_json"])
        fr_full = " ".join([l["fr"] for l in lines])
        de_full = " ".join([l["de"] for l in lines])
        
        chat_html = ""
        for l in lines:
            speaker = "👤 Personne A" if l["spk"] == "A" else "👥 Personne B"
            color = "#E8F6FD" if l["spk"] == "A" else "#D4F5E3"
            chat_html += f"""
            <div style="margin-bottom:10px; padding:10px; border-radius:10px; background:{color};">
                <div style="font-size:11px; font-weight:bold; color:#5B7A90;">{speaker}</div>
                <div style="font-size:16px; font-weight:bold;">{l['de']}</div>
                <div style="font-size:13px; color:#5B7A90;">{l['fr']}</div>
            </div>
            """
            
        cards += f"""
        <div class="card">
            <h3>{r['title']}</h3>
            <div style="margin:10px 0;">
                {say_btn("▶ Écouter (FR puis DE)", "pair", fr_full, de_full, css="primary")}
            </div>
            <div style="max-height: 300px; overflow-y: auto; padding-right: 10px;">
                {chat_html}
            </div>
        </div>
        """

    body = f"""
    <h1>Dialogues du quotidien 🗣️</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">50 dialogues de la vie réelle. Écoute-les en entier ou lance la playlist pour tout enchaîner.</p>
    {cards}
    """
    return render_template_string(layout("Dialogues", body, {"is_admin": session.get("is_admin")}))

@app.route("/playlists")
@login_required
def playlists():
    db = get_db()
    
    cats_lessons = db.execute("SELECT DISTINCT category FROM lessons ORDER BY category").fetchall()
    playlist_data_lessons = {}
    for c in cats_lessons:
        items = db.execute("SELECT french, german FROM lessons WHERE category=? ORDER BY order_index", (c["category"],)).fetchall()
        playlist_data_lessons[c["category"]] = [{"fr": i["french"], "de": i["german"]} for i in items]

    cats_vocab = db.execute("SELECT DISTINCT category FROM vocab ORDER BY category").fetchall()
    playlist_data_vocab = {}
    for c in cats_vocab:
        items = db.execute("SELECT french, german FROM vocab WHERE category=? ORDER BY id", (c["category"],)).fetchall()
        playlist_data_vocab[c["category"]] = [{"fr": i["french"], "de": i["german"]} for i in items]

    d_rows = db.execute("SELECT * FROM dialogues").fetchall()
    playlist_data_dialogues = {}
    for r in d_rows:
        lines = json.loads(r["lines_json"])
        playlist_data_dialogues[r["title"]] = [{"fr": l["fr"], "de": l["de"]} for l in lines]
        
    num_rows = db.execute("SELECT french, german FROM vocab WHERE category='Nombres' ORDER BY id").fetchall()
    playlist_data_numbers = {"Nombres 0-1000": [{"fr": i["french"], "de": i["german"]} for i in num_rows]}

    order_l = [r["category"] for r in db.execute(
        "SELECT category FROM lessons GROUP BY category ORDER BY MIN(order_index), MIN(id)").fetchall()]
    order_v = [r["category"] for r in db.execute(
        "SELECT category FROM vocab GROUP BY category ORDER BY MIN(id)").fetchall()]
    order_d = [r["title"] for r in d_rows]

    n_lessons = sum(len(v) for v in playlist_data_lessons.values())
    n_vocab = sum(len(v) for v in playlist_data_vocab.values())
    n_dialogues = sum(len(v) for v in playlist_data_dialogues.values())
    n_numbers = len(playlist_data_numbers["Nombres 0-1000"])

    js_data = json.dumps({
        "lessons": playlist_data_lessons,
        "vocab": playlist_data_vocab,
        "dialogues": playlist_data_dialogues,
        "numbers": playlist_data_numbers,
        "order": {"lessons": order_l, "vocab": order_v, "dialogues": order_d}
    }, ensure_ascii=False).replace("</", "<\\/")

    cards_all = f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Tous les cours</h3>
                <p style="color:#5B7A90;font-size:14px;margin:4px 0 0 0">{n_lessons} phrases en un seul bloc.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "lessons", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Tout le vocabulaire</h3>
                <p style="color:#5B7A90;font-size:14px;margin:4px 0 0 0">{n_vocab} mots en un seul bloc.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "vocab", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Tous les dialogues</h3>
                <p style="color:#5B7A90;font-size:14px;margin:4px 0 0 0">{n_dialogues} répliques (50 dialogues).</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "dialogues", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Les nombres 0 à 1000</h3>
                <p style="color:#5B7A90;font-size:14px;margin:4px 0 0 0">{n_numbers} nombres lus à la suite.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "numbers", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center; background: #D4F5E3;">
            <div>
                <h3 style="margin:0">Tout NATHO (Phrases + Vocab + Dialogues)</h3>
                <p style="color:#1E7A45;font-size:14px;margin:4px 0 0 0">{n_lessons + n_vocab + n_dialogues} éléments.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "mix", css="btn ok")}
        </div>
    """

    cards_lessons = ""
    for c in cats_lessons:
        cards_lessons += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{c['category']}</h3>
                <p style="color:#5B7A90;font-size:14px;margin:4px 0 0 0">Leçons de cours.</p>
            </div>
            {playlist_btn("▶ Playlist", "lessons", c['category'], css="btn ok")}
        </div>
        """

    cards_vocab = ""
    for c in cats_vocab:
        cards_vocab += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{c['category']}</h3>
                <p style="color:#5B7A90;font-size:14px;margin:4px 0 0 0">Mots de vocabulaire.</p>
            </div>
            {playlist_btn("▶ Playlist", "vocab", c['category'], css="btn")}
        </div>
        """
        
    cards_dialogues = ""
    for c in order_d:
        cards_dialogues += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{c}</h3>
                <p style="color:#5B7A90;font-size:14px;margin:4px 0 0 0">Dialogue.</p>
            </div>
            {playlist_btn("▶ Playlist", "dialogues", c, css="btn")}
        </div>
        """

    body = f"""
    <h1>Playlists Audio 🎵</h1>
    <p style="margin-bottom:20px;color:#5B7A90;">Le mode Spotify de NATHO. Choisis ce que tu veux écouter.</p>

    <h2>🎧 Blocs complets</h2>
    {cards_all}

    <h2 style="margin-top:30px;">🗣️ Dialogues du quotidien</h2>
    {cards_dialogues}

    <h2 style="margin-top:30px;">📚 Playlists de Cours</h2>
    {cards_lessons}

    <h2 style="margin-top:30px;">📖 Playlists de Vocabulaire</h2>
    {cards_vocab}

    <script>{{% raw %}}window.NATHO_PLAYLISTS = {js_data};{{% endraw %}}</script>
    """
    return render_template_string(layout("Playlists", body, {"is_admin": session.get("is_admin")}))

@app.route("/progress")
@login_required
def progress():
    db = get_db()
    rows = db.execute("""
      SELECT l.id, l.category, l.german, l.french,
             COALESCE(p.listened,0) as listened,
             COALESCE(p.completed,0) as completed
      FROM lessons l LEFT JOIN progress p
        ON p.lesson_id=l.id AND p.user_id=?
      ORDER BY l.category, l.order_index
    """, (session["user_id"],)).fetchall()
    rows_html = ""
    for r in rows:
        badge = '<span class="badge done">✔</span>' if r["completed"] else (
                '<span class="badge todo">⏯</span>' if r["listened"] else '—')
        play_btn = say_btn("▶ Écouter", "pair", r["french"], r["german"],
                           css="btn ghost", style="padding:6px 12px;font-size:12px")
        rows_html += f"<tr><td>{r['category']}</td><td><b>{r['german']}</b></td><td>{r['french']}</td><td>{badge}</td><td>{play_btn}</td></tr>"

    g_results = db.execute("SELECT * FROM goethe_exam WHERE user_id=? ORDER BY taken_at DESC LIMIT 5", (session["user_id"],)).fetchall()
    g_html = ""
    for ex in g_results:
        try:
            data = json.loads(ex["result_json"])
            s_html = f"<b>{data.get('score',0)}/{data.get('total',0)}</b> - {data.get('level','A1')}"
        except Exception:
            s_html = "Erreur"
        g_html += f"<tr><td>{ex['taken_at']}</td><td>{s_html}</td></tr>"

    if not g_html:
        g_html = "<tr><td colspan='2'>Aucun examen Goethe passé pour le moment.</td></tr>"

    body = f"""
    <h1>Mes progrès</h1>
    <div class="card">
      <h2>Leçons</h2>
      <table><thead><tr><th>Catégorie</th><th>Allemand</th><th>Français</th><th>État</th><th>Audio</th></tr></thead>
      <tbody>{rows_html}</tbody></table>
    </div>
    <div class="card">
      <h2>Mes examens Goethe</h2>
      <table><thead><tr><th>Date</th><th>Résultat</th></tr></thead><tbody>{g_html}</tbody></table>
    </div>
    """
    return render_template_string(layout("Progrès", body, {"is_admin": session.get("is_admin")}))

# ---------------------------------------------------------
# PAGES LÉGALES & POLITIQUES
# ---------------------------------------------------------
@app.route("/politique")
def politique():
    user = None
    if "user_id" in session:
        user = {"is_admin": session.get("is_admin")}
    body = """
    <h1>Politique de confidentialité</h1>
    <div class="card">
        <h2>1. Collecte des données</h2>
        <p>NATHO collecte uniquement votre nom, votre adresse email et vos résultats d'apprentissage. Ces données sont strictement confidentielles et ne sont jamais vendues à des tiers.</p>
        
        <h2>2. Utilisation des cookies</h2>
        <p>Nous utilisons des cookies pour :
        <br>- Maintenir votre session connectée.
        <br>- Mémoriser vos préférences audio (volume, vitesse).
        <br>- Sauvegarder votre progression dans les playlists (pour reprendre là où vous vous êtes arrêté).</p>
        
        <h2>3. Sécurité</h2>
        <p>Les mots de passe sont chiffrés. Nous vous recommandons d'utiliser un mot de passe fort (majuscule, minuscule, chiffre).</p>
        
        <h2>4. Vos droits</h2>
        <p>Conformément au RGPD, vous pouvez demander la suppression de votre compte et de vos données à tout moment en contactant l'administrateur.</p>
    </div>
    <a href="/" class="btn ghost">← Retour à l'accueil</a>
    """
    return render_template_string(layout("Politique de confidentialité", body, user))

@app.route("/cgu")
def cgu():
    user = None
    if "user_id" in session:
        user = {"is_admin": session.get("is_admin")}
    body = """
    <h1>Conditions Générales d'Utilisation</h1>
    <div class="card">
        <h2>1. Objet</h2>
        <p>NATHO est une plateforme d'apprentissage de l'allemand destinée aux débutants (Niveau A1).</p>

        <h2>2. Propriété intellectuelle (IMPORTANT)</h2>
        <p>L'ensemble du contenu (textes, audios, questions d'examen, code source, design) est la propriété exclusive de NATHO. <strong>Toute reproduction, copie, modification ou revente non autorisée est strictement interdite et protégée par les lois sur le droit d'auteur.</strong></p>

        <h2>3. Utilisation</h2>
        <p>Vous vous engagez à ne pas partager vos identifiants de connexion. L'outil est destiné à un usage personnel et pédagogique.</p>

        <h2>4. Responsabilité</h2>
        <p>NATHO ne délivre pas de certificat officiel Goethe. Les examens proposés sont des simulations pour l'entraînement.</p>
    </div>
    <a href="/" class="btn ghost">← Retour à l'accueil</a>
    """
    return render_template_string(layout("CGU", body, user))

@app.route("/mentions")
def mentions():
    user = None
    if "user_id" in session:
        user = {"is_admin": session.get("is_admin")}
    body = """
    <h1>Mentions Légales</h1>
    <div class="card">
        <p><strong>Éditeur :</strong> NATHO Platform</p>
        <p><strong>Contact :</strong> admin@natho.com</p>
        <p><strong>Hébergement :</strong> Railway (Cloud)</p>
        <p><strong>Directeur de publication :</strong> L'équipe NATHO</p>
        <p>Cette plateforme est un prototype en cours de développement.</p>
    </div>
    <a href="/" class="btn ghost">← Retour à l'accueil</a>
    """
    return render_template_string(layout("Mentions légales", body, user))

# ---------------------------------------------------------
# EXAMEN GOETHE A1
# ---------------------------------------------------------
HOREN_QUESTIONS = [
    {"audio": "Guten Tag! Ich möchte eine Fahrkarte nach Berlin kaufen.", "q": "Que veut acheter la personne ?", "opts": ["Un billet pour Berlin", "Un café", "Un livre"], "ans": "0"},
    {"audio": "Wo ist der Bahnhof, bitte?", "q": "Que cherche la personne ?", "opts": ["La gare", "L'hôpital", "La banque"], "ans": "0"},
    {"audio": "Ich hätte gern ein Wasser, bitte.", "q": "Que commande la personne ?", "opts": ["De l'eau", "Du vin", "Un café"], "ans": "0"},
    {"audio": "Wie viel kostet dieses Hemd?", "q": "Que demande la personne ?", "opts": ["Le prix d'une chemise", "L'heure", "Le chemin"], "ans": "0"},
    {"audio": "Können Sie mir helfen?", "q": "Que demande la personne ?", "opts": ["De l'aide", "De l'argent", "Un taxi"], "ans": "0"},
    {"audio": "Ich bin krank, ich brauche einen Arzt.", "q": "De quoi a besoin la personne ?", "opts": ["D'un médecin", "D'un avocat", "D'un professeur"], "ans": "0"},
    {"audio": "Wann fährt der Zug nach Paris?", "q": "Quelle est la question ?", "opts": ["L'heure du train pour Paris", "Le prix du train", "Le quai du train"], "ans": "0"},
    {"audio": "Mein Name ist Thomas.", "q": "Quel est le nom de la personne ?", "opts": ["Thomas", "Pierre", "Paul"], "ans": "0"},
    {"audio": "Ich wohne in Berlin.", "q": "Où habite la personne ?", "opts": ["À Berlin", "À Paris", "À Londres"], "ans": "0"},
    {"audio": "Ich suche die Toilette.", "q": "Que cherche la personne ?", "opts": ["Les toilettes", "La sortie", "L'entrée"], "ans": "0"},
    {"audio": "Der Supermarkt ist heute geschlossen.", "q": "Le supermarché est-il ouvert ?", "opts": ["Non, il est fermé", "Oui, il est ouvert", "Je ne sais pas"], "ans": "0"},
    {"audio": "Ich möchte ein Zimmer für zwei Nächte buchen.", "q": "Pour combien de nuits ?", "opts": ["Deux nuits", "Une nuit", "Trois nuits"], "ans": "0"},
    {"audio": "Wo ist die nächste Apotheke?", "q": "Que cherche la personne ?", "opts": ["La pharmacie", "La boulangerie", "La banque"], "ans": "0"},
    {"audio": "Kann ich mit Karte bezahlen?", "q": "Comment veut payer la personne ?", "opts": ["Par carte", "En espèces", "Par chèque"], "ans": "0"},
    {"audio": "Ich habe Kopfschmerzen.", "q": "Quel est le problème ?", "opts": ["Mal à la tête", "Mal au ventre", "Mal aux dents"], "ans": "0"},
    {"audio": "Wann beginnt der Kurs?", "q": "Que demande la personne ?", "opts": ["L'heure du cours", "Le prix du cours", "Le lieu du cours"], "ans": "0"},
    {"audio": "Ich verstehe nicht.", "q": "Que dit la personne ?", "opts": ["Elle ne comprend pas", "Elle comprend", "Elle est d'accord"], "ans": "0"},
    {"audio": "Können Sie das wiederholen?", "q": "Que demande la personne ?", "opts": ["De répéter", "De parler plus vite", "De partir"], "ans": "0"},
    {"audio": "Ich komme aus Kamerun.", "q": "D'où vient la personne ?", "opts": ["Du Cameroun", "Du Canada", "Du Cambodge"], "ans": "0"},
    {"audio": "Das Wetter ist schön heute.", "q": "Quel temps fait-il ?", "opts": ["Beau", "Mauvais", "Pluvieux"], "ans": "0"},
    {"audio": "Ich habe zwei Brüder.", "q": "Combien de frères a la personne ?", "opts": ["Deux", "Un", "Trois"], "ans": "0"},
    {"audio": "Ich arbeite als Lehrer.", "q": "Quel est le métier de la personne ?", "opts": ["Enseignant", "Médecin", "Ingénieur"], "ans": "0"},
    {"audio": "Wo ist mein Schlüssel?", "q": "Que cherche la personne ?", "opts": ["Sa clé", "Son portefeuille", "Son téléphone"], "ans": "0"},
    {"audio": "Wie spät ist es?", "q": "Quelle est la question ?", "opts": ["L'heure", "La date", "Le jour"], "ans": "0"},
    {"audio": "Ich möchte bestellen.", "q": "Que veut faire la personne ?", "opts": ["Commander", "Payer", "Partir"], "ans": "0"},
    {"audio": "Das ist zu teuer.", "q": "Que pense la personne du prix ?", "opts": ["Trop cher", "Pas cher", "Correct"], "ans": "0"},
    {"audio": "Ich brauche ein Taxi.", "q": "De quoi a besoin la personne ?", "opts": ["Un taxi", "Un bus", "Un train"], "ans": "0"},
    {"audio": "Meine Familie ist groß.", "q": "Comment est la famille ?", "opts": ["Grande", "Petite", "Moyenne"], "ans": "0"},
    {"audio": "Ich trinke gern Kaffee.", "q": "Qu'aime boire la personne ?", "opts": ["Du café", "Du thé", "De l'eau"], "ans": "0"},
    {"audio": "Wann hast du Zeit?", "q": "Que demande la personne ?", "opts": ["Quand tu as le temps", "Où tu es", "Qui tu es"], "ans": "0"},
    {"audio": "Ich wohne in einer Wohnung.", "q": "Où habite la personne ?", "opts": ["Dans un appartement", "Dans une maison", "À l'hôtel"], "ans": "0"},
    {"audio": "Der Zug hat Verspätung.", "q": "Quel est le problème ?", "opts": ["Le train est en retard", "Le train est annulé", "Le train est à l'heure"], "ans": "0"},
    {"audio": "Ich möchte das Hemd anprobieren.", "q": "Que veut faire la personne ?", "opts": ["Essayer la chemise", "Acheter la chemise", "Rendre la chemise"], "ans": "0"},
    {"audio": "Wo ist die Kasse?", "q": "Que cherche la personne ?", "opts": ["La caisse", "La sortie", "Les toilettes"], "ans": "0"},
    {"audio": "Ich bin müde.", "q": "Comment se sent la personne ?", "opts": ["Fatiguée", "En forme", "Malade"], "ans": "0"},
    {"audio": "Das Essen ist sehr lecker.", "q": "Comment est la nourriture ?", "opts": ["Très bonne", "Mauvaise", "Correcte"], "ans": "0"},
    {"audio": "Ich lerne Deutsch seit zwei Monaten.", "q": "Depuis combien de temps ?", "opts": ["2 mois", "2 ans", "2 semaines"], "ans": "0"},
    {"audio": "Kannst du mir das Salz geben?", "q": "Que demande la personne ?", "opts": ["Le sel", "Le poivre", "L'eau"], "ans": "0"},
    {"audio": "Ich habe keine Zeit heute.", "q": "Pourquoi la personne ne vient pas ?", "opts": ["Elle n'a pas le temps", "Elle est malade", "Elle est en vacances"], "ans": "0"},
    {"audio": "Wo ist der Aufzug?", "q": "Que cherche la personne ?", "opts": ["L'ascenseur", "L'escalier", "La sortie"], "ans": "0"},
    {"audio": "Ich möchte einen Tisch für zwei Personen reservieren.", "q": "Pour combien de personnes ?", "opts": ["Deux", "Une", "Trois"], "ans": "0"},
    {"audio": "Das Zimmer ist sehr sauber.", "q": "Comment est la chambre ?", "opts": ["Très propre", "Sale", "Moyenne"], "ans": "0"},
    {"audio": "Ich gehe jeden Tag spazieren.", "q": "Que fait la personne chaque jour ?", "opts": ["Elle se promène", "Elle court", "Elle nage"], "ans": "0"},
    {"audio": "Wann ist das Frühstück?", "q": "Que demande la personne ?", "opts": ["L'heure du petit-déjeuner", "Le prix", "Le lieu"], "ans": "0"},
    {"audio": "Ich brauche eine Quittung.", "q": "Que demande la personne ?", "opts": ["Un reçu", "Une facture", "Un ticket"], "ans": "0"},
    {"audio": "Mein Handy ist kaputt.", "q": "Quel est le problème ?", "opts": ["Le téléphone est cassé", "Le téléphone est perdu", "Le téléphone est neuf"], "ans": "0"},
    {"audio": "Ich möchte Geld abheben.", "q": "Que veut faire la personne ?", "opts": ["Retirer de l'argent", "Déposer de l'argent", "Emprunter de l'argent"], "ans": "0"},
    {"audio": "Die Bank ist neben dem Supermarkt.", "q": "Où est la banque ?", "opts": ["À côté du supermarché", "En face du supermarché", "Derrière le supermarché"], "ans": "0"},
    {"audio": "Ich fahre mit dem Fahrrad zur Arbeit.", "q": "Comment va-t-il au travail ?", "opts": ["À vélo", "En bus", "À pied"], "ans": "0"},
    {"audio": "Ich habe einen Termin um zehn Uhr.", "q": "À quelle heure est le rendez-vous ?", "opts": ["10h", "11h", "12h"], "ans": "0"},
    {"audio": "Ich suche eine neue Wohnung.", "q": "Que cherche la personne ?", "opts": ["Un appartement", "Une maison", "Un hôtel"], "ans": "0"}
]

LESEN_QUESTIONS = [
    {"text": "Hallo Anna, ich komme heute später, weil ich noch einkaufen muss. Wir treffen uns um 19 Uhr im Restaurant. Bis später, Tom.", "q": "Pourquoi Tom arrive-t-il plus tard ?", "opts": ["Il doit faire des courses", "Il est malade", "Il travaille"], "ans": "0"},
    {"text": "Liebe Maria, vielen Dank für die Einladung. Ich komme gern zu deiner Party am Samstag. Bis bald!", "q": "Que répond l'auteur ?", "opts": ["Il accepte l'invitation", "Il refuse l'invitation", "Il ne sait pas"], "ans": "0"},
    {"text": "Achtung: Der Supermarkt ist heute wegen Renovierung geschlossen.", "q": "Pourquoi le supermarché est-il fermé ?", "opts": ["Pour rénovation", "Pour les vacances", "Pour une grève"], "ans": "0"},
    {"text": "Ich heiße Sophie. Ich bin 25 Jahre alt und komme aus Frankreich. Ich arbeite als Lehrerin.", "q": "Quel est le métier de Sophie ?", "opts": ["Professeure", "Médecin", "Ingénieure"], "ans": "0"},
    {"text": "Bitte rufen Sie mich unter der Nummer 0123456789 an.", "q": "Que demande la personne ?", "opts": ["D'appeler un numéro", "D'envoyer un mail", "D'écrire une lettre"], "ans": "0"},
    {"text": "Das Hotel ist sehr schön und das Frühstück ist inklusive.", "q": "Qu'est-ce qui est inclus ?", "opts": ["Le petit-déjeuner", "Le dîner", "La piscine"], "ans": "0"},
    {"text": "Ich kann heute nicht kommen, ich habe keine Zeit. Morgen ist besser.", "q": "Pourquoi la personne ne vient pas ?", "opts": ["Elle n'a pas le temps", "Elle est malade", "Elle est en vacances"], "ans": "0"},
    {"text": "Der Kurs beginnt um 9 Uhr und endet um 12 Uhr.", "q": "Quand commence le cours ?", "opts": ["À 9 heures", "À 10 heures", "À 12 heures"], "ans": "0"},
    {"text": "Entschuldigung, wo ist die Apotheke? Ich brauche Medikamente.", "q": "Que cherche la personne ?", "opts": ["La pharmacie", "La boulangerie", "La banque"], "ans": "0"},
    {"text": "Ich habe zwei Kinder, einen Jungen und ein Mädchen.", "q": "Combien d'enfants a la personne ?", "opts": ["Deux", "Un", "Trois"], "ans": "0"},
    {"text": "Der Zug nach München hat 20 Minuten Verspätung.", "q": "Combien de retard a le train ?", "opts": ["20 minutes", "10 minutes", "30 minutes"], "ans": "0"},
    {"text": "Am Montag habe ich einen Arzttermin.", "q": "Quand est le rendez-vous chez le médecin ?", "opts": ["Lundi", "Mardi", "Mercredi"], "ans": "0"},
    {"text": "Ich suche eine neue Wohnung in der Stadt.", "q": "Que cherche la personne ?", "opts": ["Un appartement", "Une maison", "Un hôtel"], "ans": "0"},
    {"text": "Das Essen im Restaurant war sehr lecker.", "q": "Comment était la nourriture ?", "opts": ["Très bonne", "Mauvaise", "Correcte"], "ans": "0"},
    {"text": "Ich fahre am Wochenende mit dem Fahrrad.", "q": "Que fait la personne ce week-end ?", "opts": ["Du vélo", "De la voiture", "De la marche"], "ans": "0"},
    {"text": "Mein Bruder wohnt in Berlin.", "q": "Où habite le frère ?", "opts": ["À Berlin", "À Paris", "À Londres"], "ans": "0"},
    {"text": "Die Jacke kostet 50 Euro.", "q": "Combien coûte la veste ?", "opts": ["50 euros", "40 euros", "60 euros"], "ans": "0"},
    {"text": "Ich möchte einen Tisch für zwei Personen reservieren.", "q": "Pour combien de personnes ?", "opts": ["Deux", "Une", "Trois"], "ans": "0"},
    {"text": "Das Wetter ist heute schlecht, es regnet.", "q": "Quel temps fait-il ?", "opts": ["Il pleut", "Il neige", "Il fait beau"], "ans": "0"},
    {"text": "Ich lerne Deutsch seit drei Monaten.", "q": "Depuis combien de temps apprend-il l'allemand ?", "opts": ["3 mois", "3 ans", "3 semaines"], "ans": "0"},
    {"text": "Bitte schicken Sie mir eine E-Mail.", "q": "Que demande la personne ?", "opts": ["Un email", "Un appel", "Une lettre"], "ans": "0"},
    {"text": "Ich habe meine Hausaufgaben gemacht.", "q": "Qu'a fait la personne ?", "opts": ["Ses devoirs", "La cuisine", "Le ménage"], "ans": "0"},
    {"text": "Der Supermarkt ist bis 20 Uhr geöffnet.", "q": "Jusqu'à quelle heure est ouvert le supermarché ?", "opts": ["20h", "18h", "22h"], "ans": "0"},
    {"text": "Ich brauche einen neuen Computer.", "q": "De quoi a besoin la personne ?", "opts": ["Un ordinateur", "Un téléphone", "Une télévision"], "ans": "0"},
    {"text": "Meine Schwester ist 18 Jahre alt.", "q": "Quel âge a la sœur ?", "opts": ["18 ans", "20 ans", "16 ans"], "ans": "0"},
    {"text": "Ich fahre morgen nach Hamburg.", "q": "Où va la personne ?", "opts": ["À Hambourg", "À Munich", "À Berlin"], "ans": "0"},
    {"text": "Das Zimmer ist sehr groß und hell.", "q": "Comment est la chambre ?", "opts": ["Grande et lumineuse", "Petite et sombre", "Moyenne"], "ans": "0"},
    {"text": "Ich trinke morgens einen Kaffee.", "q": "Que boit la personne le matin ?", "opts": ["Un café", "Un thé", "Un jus"], "ans": "0"},
    {"text": "Wir treffen uns vor dem Kino.", "q": "Où se retrouvent-ils ?", "opts": ["Devant le cinéma", "Dans le cinéma", "Derrière le cinéma"], "ans": "0"},
    {"text": "Ich habe keine Zeit für Sport.", "q": "Que dit la personne ?", "opts": ["Elle n'a pas le temps", "Elle aime le sport", "Elle fait du sport"], "ans": "0"},
    {"text": "Das Buch kostet 15 Euro und ist sehr interessant.", "q": "Combien coûte le livre ?", "opts": ["15 euros", "10 euros", "20 euros"], "ans": "0"},
    {"text": "Ich fliege nächste Woche nach Spanien.", "q": "Où va la personne la semaine prochaine ?", "opts": ["En Espagne", "En France", "En Italie"], "ans": "0"},
    {"text": "Meine Mutter kocht heute Abend Suppe.", "q": "Que prépare la mère ce soir ?", "opts": ["De la soupe", "De la pizza", "Des pâtes"], "ans": "0"},
    {"text": "Der Film beginnt um 20 Uhr.", "q": "Quand commence le film ?", "opts": ["À 20h", "À 19h", "À 21h"], "ans": "0"},
    {"text": "Ich brauche ein Taxi zum Flughafen.", "q": "Où veut aller la personne ?", "opts": ["À l'aéroport", "À la gare", "À l'hôtel"], "ans": "0"},
    {"text": "Das Frühstück ist von 7 bis 10 Uhr.", "q": "Quand est servi le petit-déjeuner ?", "opts": ["De 7h à 10h", "De 8h à 11h", "De 6h à 9h"], "ans": "0"},
    {"text": "Ich habe meinen Pass verloren.", "q": "Qu'a perdu la personne ?", "opts": ["Son passeport", "Son portefeuille", "Sa clé"], "ans": "0"},
    {"text": "Die Party ist am Samstag bei Anna.", "q": "Où est la fête ?", "opts": ["Chez Anna", "Au restaurant", "Au parc"], "ans": "0"},
    {"text": "Ich kann heute nicht kommen, ich bin krank.", "q": "Pourquoi la personne ne vient pas ?", "opts": ["Elle est malade", "Elle travaille", "Elle est en vacances"], "ans": "0"},
    {"text": "Bitte öffnen Sie das Fenster.", "q": "Que demande la personne ?", "opts": ["D'ouvrir la fenêtre", "De fermer la porte", "D'allumer la lumière"], "ans": "0"},
    {"text": "Mein Vater arbeitet in einem Büro.", "q": "Où travaille le père ?", "opts": ["Dans un bureau", "Dans un hôpital", "Dans une école"], "ans": "0"},
    {"text": "Ich möchte eine Fahrkarte nach Köln kaufen.", "q": "Où veut aller la personne ?", "opts": ["À Cologne", "À Berlin", "À Munich"], "ans": "0"},
    {"text": "Das Konzert war sehr schön.", "q": "Comment était le concert ?", "opts": ["Très beau", "Mauvais", "Correct"], "ans": "0"},
    {"text": "Ich habe einen Hund und zwei Katzen.", "q": "Combien d'animaux a la personne ?", "opts": ["3", "2", "1"], "ans": "0"},
    {"text": "Der Arzt sagt, ich muss viel Wasser trinken.", "q": "Que conseille le médecin ?", "opts": ["Boire beaucoup d'eau", "Manger moins", "Dormir plus"], "ans": "0"},
    {"text": "Ich gehe jeden Tag um 7 Uhr zur Arbeit.", "q": "À quelle heure va-t-il au travail ?", "opts": ["À 7h", "À 8h", "À 9h"], "ans": "0"},
    {"text": "Wir haben eine neue Wohnung gefunden.", "q": "Qu'ont-ils trouvé ?", "opts": ["Un appartement", "Une maison", "Un travail"], "ans": "0"},
    {"text": "Das Hotel kostet 80 Euro pro Nacht.", "q": "Combien coûte l'hôtel par nuit ?", "opts": ["80 euros", "60 euros", "100 euros"], "ans": "0"},
    {"text": "Ich lerne Deutsch, weil ich in Deutschland arbeiten möchte.", "q": "Pourquoi apprend-il l'allemand ?", "opts": ["Pour travailler en Allemagne", "Pour voyager", "Pour le plaisir"], "ans": "0"},
    {"text": "Der Zug fährt von Gleis 5 ab.", "q": "De quel quai part le train ?", "opts": ["Le quai 5", "Le quai 3", "Le quai 7"], "ans": "0"},
    {"text": "Bitte bringen Sie mir die Speisekarte.", "q": "Que demande la personne ?", "opts": ["Le menu", "L'addition", "Un verre d'eau"], "ans": "0"}
]

SCHREIBEN_QUESTIONS = [
    {"q": "Écris un message à un ami pour l'inviter à dîner ce soir. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu es malade et que tu ne peux pas venir au cours. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander le prix d'un billet de train pour Munich. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour t'excuser d'être en retard au rendez-vous. (Entschuldigung, ...)", "min_words": 5},
    {"q": "Écris un message pour remercier ton ami pour le cadeau. (Liebe/r ..., ...)", "min_words": 5},
    {"q": "Écris un message pour annuler un rendez-vous. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander le chemin vers la gare. (Entschuldigung, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu as trouvé un nouvel appartement. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour inviter un ami à faire du sport. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander un rendez-vous chez le médecin. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu es arrivé à Berlin. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander le prix d'un hôtel. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour remercier pour l'aide. (Vielen Dank, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu as oublié ton livre. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour proposer de sortir ce week-end. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu ne trouves pas l'adresse. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander une facture. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu as aimé le film. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander un conseil. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu as reçu le colis. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour commander un livre sur internet. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour t'excuser d'avoir oublié l'anniversaire de ton ami. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu cherches un travail. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander l'heure du train. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour inviter ta famille à Noël. (Liebe Familie, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu as perdu ton portefeuille. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander un remboursement. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour proposer ton aide à un ami. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu es en vacances. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander le code Wi-Fi. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu as changé de numéro de téléphone. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour remercier pour l'invitation. (Vielen Dank, ...)", "min_words": 5},
    {"q": "Écris un message pour demander un rendez-vous chez le coiffeur. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu ne peux pas venir à la fête. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander des informations sur un cours. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu as trouvé un chat. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander l'adresse de l'hôtel. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour proposer une réunion. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu es content de venir. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander un conseil de lecture. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu as besoin de repos. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour commander un taxi. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu as raté ton bus. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour inviter un ami à une exposition. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander le menu du jour. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu as acheté une nouvelle voiture. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour remercier pour le cadeau d'anniversaire. (Liebe/r ..., ...)", "min_words": 5},
    {"q": "Écris un message pour demander l'heure de fermeture du magasin. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu es à la maison. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour proposer de faire les courses ensemble. (Hallo, ...)", "min_words": 5}
]

SPRECHEN_QUESTIONS = [
    {"q": "Présente-toi : Dis ton nom, ton pays, ta ville et ta langue maternelle.", "example": "Hallo! Ich heiße Thomas. Ich komme aus Kamerun. Ich wohne in Douala. Ich lerne Deutsch."},
    {"q": "Épelle ton nom de famille lentement à voix haute.", "example": "M-A-R-T-I-N"},
    {"q": "Dis à voix haute que tu aimes le café et que tu n'aimes pas le thé.", "example": "Ich mag Kaffee, aber ich mag keinen Tee."},
    {"q": "Dis les jours de la semaine en allemand.", "example": "Montag, Dienstag, Mittwoch, Donnerstag, Freitag, Samstag, Sonntag."},
    {"q": "Commande un café et un croissant dans un restaurant à voix haute.", "example": "Ich hätte gern einen Kaffee und ein Croissant."},
    {"q": "Dis à voix haute que tu habites à Paris.", "example": "Ich wohne in Paris."},
    {"q": "Dis que tu as deux frères et une sœur.", "example": "Ich habe zwei Brüder und eine Schwester."},
    {"q": "Demande où sont les toilettes.", "example": "Wo ist die Toilette?"},
    {"q": "Dis à voix haute que tu apprends l'allemand depuis un an.", "example": "Ich lerne Deutsch seit einem Jahr."},
    {"q": "Demande combien coûte ce livre.", "example": "Wie viel kostet dieses Buch?"},
    {"q": "Dis que tu es fatigué(e).", "example": "Ich bin müde."},
    {"q": "Demande l'heure à quelqu'un.", "example": "Wie spät ist es?"},
    {"q": "Dis que tu aimes écouter de la musique.", "example": "Ich höre gern Musik."},
    {"q": "Dis que tu ne comprends pas.", "example": "Ich verstehe nicht."},
    {"q": "Demande de répéter.", "example": "Können Sie das wiederholen?"},
    {"q": "Dis que tu habites dans un appartement.", "example": "Ich wohne in einer Wohnung."},
    {"q": "Dis à voix haute que tu as un chien et un chat.", "example": "Ich habe einen Hund und eine Katze."},
    {"q": "Demande le chemin pour aller à la gare.", "example": "Wie komme ich zum Bahnhof?"},
    {"q": "Dis que tu veux acheter un billet pour Berlin.", "example": "Ich möchte eine Fahrkarte nach Berlin kaufen."},
    {"q": "Dis que tu as besoin d'un médecin.", "example": "Ich brauche einen Arzt."},
    {"q": "Dis que tu es en retard.", "example": "Ich bin zu spät."},
    {"q": "Demande où est la pharmacie.", "example": "Wo ist die Apotheke?"},
    {"q": "Dis que tu as mal à la tête.", "example": "Ich habe Kopfschmerzen."},
    {"q": "Dis que tu aimes le chocolat.", "example": "Ich mag Schokolade."},
    {"q": "Dis que tu ne peux pas venir ce soir.", "example": "Ich kann heute Abend nicht kommen."},
    {"q": "Demande le prix de la chambre.", "example": "Wie viel kostet das Zimmer?"},
    {"q": "Dis que tu veux réserver une table.", "example": "Ich möchte einen Tisch reservieren."},
    {"q": "Dis que tu as faim.", "example": "Ich habe Hunger."},
    {"q": "Dis que tu as soif.", "example": "Ich habe Durst."},
    {"q": "Demande où se trouve le supermarché.", "example": "Wo ist der Supermarkt?"},
    {"q": "Dis que tu n'aimes pas le poisson.", "example": "Ich mag keinen Fisch."},
    {"q": "Dis que tu es content(e) de te présenter.", "example": "Ich freue mich, mich vorzustellen."},
    {"q": "Dis que tu vas partir demain.", "example": "Ich fahre morgen ab."},
    {"q": "Dis que tu travailles dans un bureau.", "example": "Ich arbeite in einem Büro."},
    {"q": "Dis à voix haute les couleurs en allemand.", "example": "Rot, blau, grün, gelb, schwarz, weiß."},
    {"q": "Dis que tu as deux enfants.", "example": "Ich habe zwei Kinder."},
    {"q": "Demande un verre d'eau.", "example": "Ein Glas Wasser, bitte."},
    {"q": "Dis que tu es prêt(e).", "example": "Ich bin bereit."},
    {"q": "Demande à qui est ce sac.", "example": "Wem gehört diese Tasche?"},
    {"q": "Dis que tu vas appeler plus tard.", "example": "Ich rufe später an."},
    {"q": "Dis que tu as oublié la clé.", "example": "Ich habe den Schlüssel vergessen."},
    {"q": "Dis que tu aimes voyager.", "example": "Ich reise gern."},
    {"q": "Dis que tu veux dormir.", "example": "Ich möchte schlafen."},
    {"q": "Dis que tu cherches un travail.", "example": "Ich suche Arbeit."},
    {"q": "Dis que tu apprends l'allemand pour travailler.", "example": "Ich lerne Deutsch, weil ich arbeiten möchte."}
]

@app.route("/goethe")
@login_required
def goethe():
    body = """
    <h1>Examen Goethe A1 (Simulateur)</h1>
    <p style="margin-bottom:20px;color:#5B7A90;">Cet examen blanc est structuré en 4 modules officiels. Il ne délivre pas de certificat officiel, mais il te prépare parfaitement aux conditions réelles.</p>

    <div class="grid">
      <div class="card">
        <h2>1. Hören (Écoute)</h2>
        <p>L'application lit un court dialogue. Tu dois choisir la bonne réponse.</p>
        <a href="/goethe/horen" class="btn">Commencer</a>
      </div>
      <div class="card">
        <h2>2. Lesen (Lecture)</h2>
        <p>Lis un court texte en allemand et réponds à des questions.</p>
        <a href="/goethe/lesen" class="btn">Commencer</a>
      </div>
      <div class="card">
        <h2>3. Schreiben (Écriture)</h2>
        <p>Remplis un formulaire ou écris un message simple.</p>
        <a href="/goethe/schreiben" class="btn">Commencer</a>
      </div>
      <div class="card">
        <h2>4. Sprechen (Parler)</h2>
        <p>Écoute une consigne, prépare-toi, et parle à voix haute.</p>
        <a href="/goethe/sprechen" class="btn">Commencer</a>
      </div>
    </div>
    """
    return render_template_string(layout("Examen Goethe A1", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/horen", methods=["GET","POST"])
@login_required
def goethe_horen():
    if request.method == "GET":
        q = random.choice(HOREN_QUESTIONS)
        session['current_horen'] = q
    else:
        q = session.get('current_horen')
        if not q:
            return redirect(url_for("goethe_horen"))
        rep = request.form.get("rep")
        score = 1 if rep == q['ans'] else 0
        feedback = "✔ Bonne réponse !" if score == 1 else f"✘ Mauvaise réponse. C'était : {q['opts'][0]}"
        body = f"""
        <h1>Hören (Écoute) - Résultat</h1>
        <div class="card">
          <div class="flash {'success' if score==1 else 'danger'}">{feedback}</div>
          <p><b>Dialogue :</b> {q['audio']}</p>
          <div style="margin:12px 0;">{say_btn("🔊 Réécouter", "de", "", q['audio'], css="btn ghost")}</div>
          <a href="/goethe/horen" class="btn">Question suivante</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return render_template_string(layout("Résultat Hören", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Hören (Écoute)</h1>
    <div class="card">
      <p>Écoute attentivement ce dialogue :</p>
      <div style="background:#E8F6FD;padding:16px;border-radius:10px;margin:14px 0;">
        {say_btn("🔊 Écouter le dialogue", "de", "", q['audio'])}
      </div>
      <form method="post">
        <h3>{q['q']}</h3>
        {''.join(f'<label class="quiz-opt"><input type="radio" name="rep" value="{i}" required> {i}. {opt}</label>' for i, opt in enumerate(q['opts']))}
        <button class="btn ok" type="submit" style="margin-top:14px">Valider</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    """
    return render_template_string(layout("Hören", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/lesen", methods=["GET","POST"])
@login_required
def goethe_lesen():
    if request.method == "GET":
        q = random.choice(LESEN_QUESTIONS)
        session['current_lesen'] = q
    else:
        q = session.get('current_lesen')
        if not q:
            return redirect(url_for("goethe_lesen"))
        rep = request.form.get("rep")
        score = 1 if rep == q['ans'] else 0
        feedback = "✔ Bonne réponse !" if score == 1 else f"✘ Mauvaise réponse. C'était : {q['opts'][0]}"
        body = f"""
        <h1>Lesen (Lecture) - Résultat</h1>
        <div class="card">
          <div class="flash {'success' if score==1 else 'danger'}">{feedback}</div>
          <p><b>Texte :</b> {q['text']}</p>
          <a href="/goethe/lesen" class="btn">Question suivante</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return render_template_string(layout("Résultat Lesen", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Lesen (Lecture)</h1>
    <div class="card">
      <p>Lis ce message :</p>
      <div style="background:#E8F6FD;padding:16px;border-radius:10px;margin:14px 0;font-style:italic;">
        "{q['text']}"
      </div>
      <form method="post">
        <h3>{q['q']}</h3>
        {''.join(f'<label class="quiz-opt"><input type="radio" name="rep" value="{i}" required> {i}. {opt}</label>' for i, opt in enumerate(q['opts']))}
        <button class="btn ok" type="submit" style="margin-top:14px">Valider</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    """
    return render_template_string(layout("Lesen", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/schreiben", methods=["GET","POST"])
@login_required
def goethe_schreiben():
    if request.method == "GET":
        q = random.choice(SCHREIBEN_QUESTIONS)
        session['current_schreiben'] = q
    else:
        q = session.get('current_schreiben')
        if not q:
            return redirect(url_for("goethe_schreiben"))
        rep = request.form.get("rep", "").strip()
        words = len(rep.split())
        score = 1 if words >= q['min_words'] else 0
        feedback = "✔ Bon travail !" if score == 1 else f"✘ C'est un peu court. Essaie d'écrire au moins {q['min_words']} mots."
        body = f"""
        <h1>Schreiben (Écriture) - Résultat</h1>
        <div class="card">
          <div class="flash {'success' if score==1 else 'danger'}">{feedback}</div>
          <p><b>Ta réponse :</b> {h(rep)}</p>
          <p style="color:#5B7A90;margin-top:10px;">Note : dans un vrai examen, un correcteur humain évalue la grammaire et le vocabulaire.</p>
          <a href="/goethe/schreiben" class="btn">Exercice suivant</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return render_template_string(layout("Résultat Schreiben", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Schreiben (Écriture)</h1>
    <div class="card">
      <p><b>Consigne :</b> {q['q']}</p>
      <form method="post">
        <label>Ton message :</label>
        <textarea name="rep" rows="4" placeholder="Écris en allemand ici..." required></textarea>
        <button class="btn ok" type="submit">Valider</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    """
    return render_template_string(layout("Schreiben", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/sprechen", methods=["GET","POST"])
@login_required
def goethe_sprechen():
    if request.method == "GET":
        q = random.choice(SPRECHEN_QUESTIONS)
        session['current_sprechen'] = q
    else:
        body = """
        <h1>Sprechen (Parler) - Terminé</h1>
        <div class="card">
          <div class="flash success">✔ Module terminé !</div>
          <p>Dans un vrai examen Goethe, l'examinateur t'écoute et évalue ta prononciation. Ici, c'est à toi de t'entraîner à voix haute.</p>
          <a href="/goethe/sprechen" class="btn">Exercice suivant</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return render_template_string(layout("Résultat Sprechen", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Sprechen (Parler)</h1>
    <div class="card">
      <h2>Consigne</h2>
      <p>{q['q']}</p>
      <div style="background:#E8F6FD;padding:16px;border-radius:10px;margin:14px 0;">
        <p style="margin-bottom:10px;"><i>Exemple : {q['example']}</i></p>
        {say_btn("🔊 Écouter l'exemple", "de", "", q['example'])}
      </div>
      <p style="margin-bottom:16px;"><b>À toi de jouer :</b> Lis l'exemple à voix haute en remplaçant par tes vraies informations. Répète plusieurs fois.</p>
      <form method="post">
        <button class="btn ok" type="submit">J'ai terminé l'exercice oral</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    """
    return render_template_string(layout("Sprechen", body, {"is_admin": session.get("is_admin")}))

# ---------------------------------------------------------
# ADMIN
# ---------------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT id,name,email,is_admin,created_at FROM users ORDER BY id").fetchall()
    lessons_count = db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
    quiz_count = db.execute("SELECT COUNT(*) FROM goethe_exam").fetchone()[0]
    users_html = "".join(
        f"<tr><td>{u['id']}</td><td>{u['name']}</td><td>{u['email']}</td>"
        f"<td>{'Oui' if u['is_admin'] else 'Non'}</td><td>{u['created_at']}</td></tr>"
        for u in users
    )
    body = f"""
    <h1>Tableau de bord Admin</h1>
    <div class="stat-grid" style="margin-bottom:18px">
      <div class="stat"><div class="num">{len(users)}</div><div class="lbl">Étudiants</div></div>
      <div class="stat"><div class="num">{lessons_count}</div><div class="lbl">Leçons</div></div>
      <div class="stat"><div class="num">{quiz_count}</div><div class="lbl">Examens Goethe passés</div></div>
    </div>
    <div class="card">
      <h2>Ajouter une leçon</h2>
      <form method="post" action="{url_for('admin_add_lesson')}">
        <label>Catégorie</label><input name="category" required>
        <label>Allemand (phrase)</label><input name="german" required>
        <label>Français (traduction)</label><input name="french" required>
        <button class="btn" type="submit">Ajouter</button>
      </form>
    </div>
    <div class="card">
      <h2>Utilisateurs</h2>
      <table><thead><tr><th>ID</th><th>Nom</th><th>Email</th><th>Admin</th><th>Inscrit le</th></tr></thead>
      <tbody>{users_html}</tbody></table>
    </div>
    """
    return render_template_string(layout("Admin", body, {"is_admin": True}))

@app.route("/admin/add_lesson", methods=["POST"])
@admin_required
def admin_add_lesson():
    cat = request.form.get("category","").strip()
    de = request.form.get("german","").strip()
    fr = request.form.get("french","").strip()
    if cat and de and fr:
        db = get_db()
        db.execute("INSERT INTO lessons(category,title,french,german) VALUES(?,?,?,?)",
                   (cat,de,fr,de))
        db.commit()
        flash("Leçon ajoutée.","success")
    else:
        flash("Champs manquants.","danger")
    return redirect(url_for("admin"))

# ---------------------------------------------------------
# LANCEMENT
# ---------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print("\n" + "="*60)
    print("  NATHO — Plateforme d'apprentissage de l'allemand A1")
    print("="*60)
    print("  URL       : http://127.0.0.1:5000")
    print("  Admin     : admin@natho.com / Achilled@vy2015")
    print("  ⚠ Change le mot de passe admin dès que possible.")
    print("="*60 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
