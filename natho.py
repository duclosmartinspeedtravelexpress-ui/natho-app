# =========================================================
# NATHO — Plateforme d'apprentissage de l'allemand A1
# Version finale stable : Sidebar + W-Fragen + Audio
# + Apprendre à parler + Essentiels A1 + Mode nuit + Menu mobile
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

        admin_email = "admin@natho.com"
        admin_pwd = "Achilled@vy2015"
        
        c.execute("SELECT * FROM users WHERE email=?", (admin_email,))
        admin_row = c.fetchone()
        
        if not admin_row:
            c.execute("INSERT INTO users(name,email,password,is_admin) VALUES(?,?,?,1)",
                      ("Admin NATHO", admin_email, hash_pwd(admin_pwd)))
        else:
            c.execute("UPDATE users SET password=?, is_admin=1 WHERE email=?", 
                      (hash_pwd(admin_pwd), admin_email))

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

        # =========================================================
        # === AJOUT : TABLES POUR "APPRENDRE À PARLER" & "ESSENTIELS A1" ===
        # Migrations idempotentes : ne détruisent JAMAIS la DB existante
        # =========================================================
        c.execute("""CREATE TABLE IF NOT EXISTS speak_phrases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            theme TEXT NOT NULL,
            theme_order INTEGER DEFAULT 0,
            fr TEXT NOT NULL,
            de TEXT NOT NULL,
            UNIQUE(fr, de)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS essentials_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fiche_num INTEGER NOT NULL UNIQUE,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            explanation TEXT NOT NULL DEFAULT ''
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS speak_playlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            key TEXT NOT NULL,
            title TEXT NOT NULL,
            items_json TEXT NOT NULL,
            UNIQUE(kind, key)
        )""")

        # Remplissage (idempotent)
        c.execute("SELECT COUNT(*) FROM lessons")
        if c.fetchone()[0] == 0:
            seed_lessons(c)
            seed_dialogues(c)
            seed_numbers(c)

        c.execute("SELECT COUNT(*) FROM lessons WHERE category='W-Fragen'")
        if c.fetchone()[0] == 0:
            seed_wfragen(c)

        c.execute("SELECT COUNT(*) FROM vocab")
        if c.fetchone()[0] == 0:
            seed_vocab(c)

        # === AJOUT : seeds idempotents pour les nouvelles tables ===
        c.execute("SELECT COUNT(*) FROM speak_phrases")
        if c.fetchone()[0] == 0:
            seed_speak_phrases(c)

        c.execute("SELECT COUNT(*) FROM essentials_cards")
        if c.fetchone()[0] == 0:
            seed_essentials_cards(c)

        seed_speak_playlists(c)  # idempotent via INSERT OR IGNORE

        db.commit()
        db.close()
    except Exception as e:
        print("❌ Erreur d'initialisation :", e)

# ---------------------------------------------------------
# CONTENU PÉDAGOGIQUE
# ---------------------------------------------------------
def seed_lessons(cursor):
    data = [
        ("Salutations", "Hallo!", "Salut ! / Bonjour !"), ("Salutations", "Guten Morgen!", "Bonjour ! (le matin)"),
        ("Salutations", "Guten Tag!", "Bonjour !"), ("Salutations", "Guten Abend!", "Bonsoir !"),
        ("Salutations", "Gute Nacht!", "Bonne nuit !"), ("Salutations", "Wie geht es dir?", "Comment vas-tu ?"),
        ("Salutations", "Wie geht es Ihnen?", "Comment allez-vous ?"), ("Salutations", "Mir geht es gut, danke.", "Je vais bien, merci."),
        ("Salutations", "Und dir?", "Et toi ?"), ("Salutations", "Auf Wiedersehen!", "Au revoir !"),
        ("Se présenter", "Ich heiße Davy.", "Je m'appelle Davy."), ("Se présenter", "Wie heißt du?", "Comment t'appelles-tu ?"),
        ("Se présenter", "Mein Name ist Davy.", "Mon nom est Davy."), ("Se présenter", "Freut mich.", "Enchanté."),
        ("Se présenter", "Ich komme aus Kamerun.", "Je viens du Cameroun."), ("Se présenter", "Woher kommst du?", "D'où viens-tu ?"),
        ("Se présenter", "Ich wohne in Paris.", "J'habite à Paris."), ("Se présenter", "Wo wohnst du?", "Où habites-tu ?"),
        ("Se présenter", "Ich bin neu hier.", "Je suis nouveau ici."),
        ("Comprendre", "Ich verstehe.", "Je comprends."), ("Comprendre", "Ich verstehe nicht.", "Je ne comprends pas."),
        ("Comprendre", "Bitte wiederholen Sie.", "Veuillez répéter, s'il vous plaît."), ("Comprendre", "Langsamer, bitte.", "Plus lentement, s'il vous plaît."),
        ("Questions", "Was ist das?", "Qu'est-ce que c'est ?"), ("Questions", "Wer ist das?", "Qui est-ce ?"),
        ("Questions", "Wo ist die Toilette?", "Où sont les toilettes ?"), ("Questions", "Wann kommst du?", "Quand viens-tu ?"),
        ("Questions", "Warum?", "Pourquoi ?"), ("Questions", "Wie viel kostet das?", "Combien cela coûte-t-il ?"),
        ("Questions", "Wie spät ist es?", "Quelle heure est-il ?"),
        ("Famille", "Das ist meine Familie.", "Voici ma famille."), ("Famille", "Das ist mein Bruder.", "Voici mon frère."),
        ("Famille", "Das ist meine Schwester.", "Voici ma sœur."), ("Famille", "Ich habe zwei Kinder.", "J'ai deux enfants."),
        ("Maison", "Ich bin zu Hause.", "Je suis à la maison."), ("Maison", "Komm bitte herein.", "Entre, s'il te plaît."),
        ("Maison", "Wo ist mein Schlüssel?", "Où est ma clé ?"),
        ("Repas", "Ich habe Hunger.", "J'ai faim."), ("Repas", "Ich habe Durst.", "J'ai soif."),
        ("Repas", "Guten Appetit!", "Bon appétit !"), ("Repas", "Die Rechnung, bitte.", "L'addition, s'il vous plaît."),
        ("Transport", "Wo ist der Bahnhof?", "Où est la gare ?"), ("Transport", "Wann fährt der Zug?", "Quand part le train ?"),
        ("Transport", "Eine Fahrkarte nach Berlin, bitte.", "Un billet pour Berlin, s'il vous plaît."),
        ("Achats", "Wie viel kostet das?", "Combien ça coûte ?"), ("Achats", "Das ist zu teuer.", "C'est trop cher."),
        ("Achats", "Wo ist die Kasse?", "Où est la caisse ?"),
        ("Temps", "Es ist acht Uhr.", "Il est huit heures."), ("Temps", "Heute habe ich Zeit.", "Aujourd'hui, j'ai le temps."),
        ("Météo", "Wie ist das Wetter heute?", "Quel temps fait-il aujourd'hui ?"), ("Météo", "Es regnet.", "Il pleut."),
        ("Santé", "Ich bin krank.", "Je suis malade."), ("Santé", "Ich brauche einen Arzt.", "J'ai besoin d'un médecin."),
        ("Urgences", "Hilfe!", "Au secours !"), ("Urgences", "Rufen Sie die Polizei!", "Appelez la police !"),
        ("Politesse", "Danke!", "Merci !"), ("Politesse", "Bitte schön.", "Je vous en prie."),
    ]
    for i, (cat, de, fr) in enumerate(data):
        cursor.execute(
            "INSERT INTO lessons(category,title,french,german,order_index) VALUES(?,?,?,?,?)",
            (cat, de, fr, de, i)
        )

def seed_wfragen(cursor):
    data = [
        ("W-Fragen", "Wer ist das?", "Qui est-ce ?"),
        ("W-Fragen", "Wer kommt heute?", "Qui vient aujourd'hui ?"),
        ("W-Fragen", "Wer hat das gesagt?", "Qui a dit ça ?"),
        ("W-Fragen", "Wer wohnt hier?", "Qui habite ici ?"),
        ("W-Fragen", "Wer sind Sie?", "Qui êtes-vous ?"),
        ("W-Fragen", "Wer ist dein Lehrer?", "Qui est ton professeur ?"),
        ("W-Fragen", "Wer hat Zeit?", "Qui a le temps ?"),
        ("W-Fragen", "Wer ist müde?", "Qui est fatigué ?"),
        ("W-Fragen", "Wer kocht das Essen?", "Qui cuisine le repas ?"),
        ("W-Fragen", "Wer arbeitet hier?", "Qui travaille ici ?"),
        ("W-Fragen", "Was machst du?", "Que fais-tu ?"),
        ("W-Fragen", "Was ist das?", "Qu'est-ce que c'est ?"),
        ("W-Fragen", "Was möchtest du trinken?", "Que veux-tu boire ?"),
        ("W-Fragen", "Was kostet das Buch?", "Combien coûte le livre ?"),
        ("W-Fragen", "Was ist dein Name?", "Quel est ton nom ?"),
        ("W-Fragen", "Was isst du gern?", "Qu'est-ce que tu aimes manger ?"),
        ("W-Fragen", "Was machst du heute Abend?", "Que fais-tu ce soir ?"),
        ("W-Fragen", "Was ist passiert?", "Que s'est-il passé ?"),
        ("W-Fragen", "Was brauchst du?", "De quoi as-tu besoin ?"),
        ("W-Fragen", "Was hast du gesagt?", "Qu'as-tu dit ?"),
        ("W-Fragen", "Wo wohnst du?", "Où habites-tu ?"),
        ("W-Fragen", "Wo ist die Toilette?", "Où sont les toilettes ?"),
        ("W-Fragen", "Wo ist der Bahnhof?", "Où est la gare ?"),
        ("W-Fragen", "Wo ist das Hotel?", "Où est l'hôtel ?"),
        ("W-Fragen", "Wo arbeitest du?", "Où travailles-tu ?"),
        ("W-Fragen", "Wo ist mein Schlüssel?", "Où est ma clé ?"),
        ("W-Fragen", "Wo kann ich parken?", "Où puis-je me garer ?"),
        ("W-Fragen", "Wo ist die Apotheke?", "Où est la pharmacie ?"),
        ("W-Fragen", "Wo ist der Supermarkt?", "Où est le supermarché ?"),
        ("W-Fragen", "Wo treffen wir uns?", "Où nous retrouvons-nous ?"),
        ("W-Fragen", "Wann kommst du?", "Quand viens-tu ?"),
        ("W-Fragen", "Wann fängt der Kurs an?", "Quand commence le cours ?"),
        ("W-Fragen", "Wann fährt der Zug?", "Quand part le train ?"),
        ("W-Fragen", "Wann hast du Geburtstag?", "Quand est ton anniversaire ?"),
        ("W-Fragen", "Wann ist das Frühstück?", "À quelle heure est le petit-déjeuner ?"),
        ("W-Fragen", "Wann gehen wir ins Kino?", "Quand allons-nous au cinéma ?"),
        ("W-Fragen", "Wann bist du fertig?", "Quand as-tu fini ?"),
        ("W-Fragen", "Wann öffnet das Geschäft?", "Quand ouvre le magasin ?"),
        ("W-Fragen", "Wann kommt der Bus?", "Quand arrive le bus ?"),
        ("W-Fragen", "Wann sehen wir uns wieder?", "Quand nous reverrons-nous ?"),
        ("W-Fragen", "Warum lernst du Deutsch?", "Pourquoi apprends-tu l'allemand ?"),
        ("W-Fragen", "Warum kommst du zu spät?", "Pourquoi viens-tu en retard ?"),
        ("W-Fragen", "Warum ist das so teuer?", "Pourquoi est-ce si cher ?"),
        ("W-Fragen", "Warum bist du traurig?", "Pourquoi es-tu triste ?"),
        ("W-Fragen", "Warum lachst du?", "Pourquoi ris-tu ?"),
        ("W-Fragen", "Warum nicht?", "Pourquoi pas ?"),
        ("W-Fragen", "Warum ist die Tür zu?", "Pourquoi la porte est-elle fermée ?"),
        ("W-Fragen", "Warum hast du keine Zeit?", "Pourquoi n'as-tu pas le temps ?"),
        ("W-Fragen", "Warum fragst du?", "Pourquoi demandes-tu ?"),
        ("W-Fragen", "Warum arbeitest du heute?", "Pourquoi travailles-tu aujourd'hui ?"),
        ("W-Fragen", "Wie heißt du?", "Comment t'appelles-tu ?"),
        ("W-Fragen", "Wie geht es dir?", "Comment vas-tu ?"),
        ("W-Fragen", "Wie alt bist du?", "Quel âge as-tu ?"),
        ("W-Fragen", "Wie kommt ich zum Bahnhof?", "Comment aller à la gare ?"),
        ("W-Fragen", "Wie viel kostet das?", "Combien cela coûte-t-il ?"),
        ("W-Fragen", "Wie spät ist es?", "Quelle heure est-il ?"),
        ("W-Fragen", "Wie ist das Wetter?", "Quel temps fait-il ?"),
        ("W-Fragen", "Wie schreibt man das?", "Comment cela s'écrit-il ?"),
        ("W-Fragen", "Wie sagt man das auf Deutsch?", "Comment dit-on cela en allemand ?"),
        ("W-Fragen", "Wie lange dauert das?", "Combien de temps cela dure-t-il ?"),
        ("W-Fragen", "Woher kommst du?", "D'où viens-tu ?"),
        ("W-Fragen", "Woher hast du das?", "D'où tiens-tu cela ?"),
        ("W-Fragen", "Woher weißt du das?", "Comment le sais-tu ?"),
        ("W-Fragen", "Woher kommt dieser Zug?", "D'où vient ce train ?"),
        ("W-Fragen", "Woher sind Sie?", "D'où êtes-vous ?"),
        ("W-Fragen", "Woher hast du dieses Buch?", "D'où as-tu ce livre ?"),
        ("W-Fragen", "Woher kommt der Lärm?", "D'où vient le bruit ?"),
        ("W-Fragen", "Woher kennen wir uns?", "D'où nous connaissons-nous ?"),
        ("W-Fragen", "Woher kommt das Wasser?", "D'où vient l'eau ?"),
        ("W-Fragen", "Woher hast du die Information?", "D'où tiens-tu l'information ?"),
        ("W-Fragen", "Wohin gehst du?", "Où vas-tu ?"),
        ("W-Fragen", "Wohin fährst du im Urlaub?", "Où vas-tu en vacances ?"),
        ("W-Fragen", "Wohin legst du das Buch?", "Où mets-tu le livre ?"),
        ("W-Fragen", "Wohin gehen wir heute Abend?", "Où allons-nous ce soir ?"),
        ("W-Fragen", "Wohin fährt dieser Bus?", "Où va ce bus ?"),
        ("W-Fragen", "Wohin hast du es gelegt?", "Où l'as-tu mis ?"),
        ("W-Fragen", "Wohin läufst du?", "Où cours-tu ?"),
        ("W-Fragen", "Wohin stellst du die Flasche?", "Où poses-tu la bouteille ?"),
        ("W-Fragen", "Wohin reist du?", "Où voyages-tu ?"),
        ("W-Fragen", "Wohin geht ihr?", "Où allez-vous ?"),
    ]
    
    cursor.execute("SELECT COALESCE(MAX(order_index), 0) FROM lessons")
    start_idx = cursor.fetchone()[0] + 1

    for i, (cat, de, fr) in enumerate(data):
        cursor.execute(
            "INSERT INTO lessons(category,title,french,german,order_index) VALUES(?,?,?,?,?)",
            (cat, de, fr, de, start_idx + i)
        )

def seed_vocab(cursor):
    vocab = [
        ("Personnes", "der Mann", "l'homme"), ("Personnes", "die Frau", "la femme"), ("Personnes", "das Kind", "l'enfant"),
        ("Personnes", "die Familie", "la famille"), ("Personnes", "der Vater", "le père"), ("Personnes", "die Mutter", "la mère"),
        ("Personnes", "der Sohn", "le fils"), ("Personnes", "die Tochter", "la fille"), ("Personnes", "der Bruder", "le frère"),
        ("Personnes", "die Schwester", "la sœur"),
        ("Maison", "das Haus", "la maison"), ("Maison", "die Wohnung", "l'appartement"), ("Maison", "das Zimmer", "la pièce / la chambre"),
        ("Maison", "die Küche", "la cuisine"), ("Maison", "das Bad", "la salle de bains"),
        ("Nourriture", "das Wasser", "l'eau"), ("Nourriture", "das Brot", "le pain"), ("Nourriture", "der Kaffee", "le café"),
        ("Nourriture", "der Tee", "le thé"), ("Nourriture", "das Bier", "la bière"),
    ]
    for cat, de, fr in vocab:
        cursor.execute("INSERT INTO vocab(category, german, french) VALUES(?,?,?)", (cat, de, fr))

def seed_dialogues(cursor):
    base_dialogues = [
        ("Au supermarché", [
            ("A", "Entschuldigung, wo ist die Milch?", "Excusez-moi, où est le lait ?"),
            ("B", "Die Milch ist dort hinten.", "Le lait est là-bas au fond."),
            ("A", "Danke. Und wo ist das Brot?", "Merci. Et où est le pain ?"),
            ("B", "Das Brot ist neben der Kasse.", "Le pain est à côté de la caisse."),
            ("A", "Hier bitte. Danke!", "Voici, s'il vous plaît. Merci !"),
            ("B", "Danke, schönen Tag noch!", "Merci, bonne journée !")
        ]),
        ("À la gare", [
            ("A", "Guten Tag, wann fährt der nächste Zug nach Berlin?", "Bonjour, quand part le prochain train pour Berlin ?"),
            ("B", "Um 14:30 Uhr, Gleis 3.", "À 14h30, voie 3."),
            ("A", "Wie lange dauert die Fahrt?", "Combien de temps dure le trajet ?"),
            ("B", "Etwa zwei Stunden.", "Environ deux heures."),
            ("A", "Hier bitte. Danke!", "Voici. Merci !"),
            ("B", "Gute Reise!", "Bon voyage !")
        ]),
    ]
    
    for title, lines in base_dialogues:
        lines_json = json.dumps([{"spk": s, "de": d, "fr": f} for s, d, f in lines])
        cursor.execute("INSERT INTO dialogues(title, lines_json) VALUES(?, ?)", (title, lines_json))

def seed_numbers(cursor):
    for i in range(0, 21):
        cursor.execute("INSERT INTO vocab(category, german, french) VALUES(?,?,?)", ("Nombres", str(i), str(i)))

# =========================================================
# === AJOUT : SEED "APPRENDRE À PARLER" (260 phrases complètes) ===
# Sujet + Verbe + Complément, TOUTES différentes de l'existant.
# =========================================================
SPEAK_PHRASES_DATA = [
    # (theme, [(fr, de), ...])
    ("Se présenter et parler de soi", [
        ("Je m'appelle Marie.", "Ich heiße Marie."),
        ("Je viens du Cameroun.", "Ich komme aus Kamerun."),
        ("J'habite à Douala.", "Ich wohne in Douala."),
        ("J'ai 25 ans.", "Ich bin 25 Jahre alt."),
        ("Je suis étudiant.", "Ich bin Student."),
        ("Je suis étudiante.", "Ich bin Studentin."),
        ("Je travaille dans un bureau.", "Ich arbeite in einem Büro."),
        ("Je parle français et anglais.", "Ich spreche Französisch und Englisch."),
        ("J'apprends l'allemand.", "Ich lerne Deutsch."),
        ("Ma langue maternelle est le français.", "Meine Muttersprache ist Französisch."),
        ("Je suis célibataire.", "Ich bin ledig."),
        ("Je suis marié(e).", "Ich bin verheiratet."),
        ("J'ai deux frères.", "Ich habe zwei Brüder."),
        ("J'ai une sœur.", "Ich habe eine Schwester."),
        ("Je suis nouveau ici.", "Ich bin neu hier."),
        ("Je suis content de te rencontrer.", "Ich freue mich, dich kennenzulernen."),
        ("Comment tu t'appelles ?", "Wie heißt du?"),
        ("Quel âge as-tu ?", "Wie alt bist du?"),
        ("D'où viens-tu ?", "Woher kommst du?"),
        ("Où habites-tu ?", "Wo wohnst du?"),
    ]),
    ("La famille et les amis", [
        ("Voici ma mère.", "Das ist meine Mutter."),
        ("Voici mon père.", "Das ist mein Vater."),
        ("J'ai deux enfants.", "Ich habe zwei Kinder."),
        ("Mon fils a cinq ans.", "Mein Sohn ist fünf Jahre alt."),
        ("Ma fille est à l'école.", "Meine Tochter ist in der Schule."),
        ("Mon frère habite à Berlin.", "Mein Bruder wohnt in Berlin."),
        ("Ma sœur est médecin.", "Meine Schwester ist Ärztin."),
        ("Mes parents habitent ici.", "Meine Eltern wohnen hier."),
        ("J'ai un cousin en Allemagne.", "Ich habe einen Cousin in Deutschland."),
        ("Ma famille est grande.", "Meine Familie ist groß."),
        ("Mon ami s'appelle Paul.", "Mein Freund heißt Paul."),
        ("Mon amie s'appelle Anna.", "Meine Freundin heißt Anna."),
        ("Nous sommes une famille de quatre.", "Wir sind eine Familie von vier."),
        ("Tu es marié(e) ?", "Bist du verheiratet?"),
        ("Je rends visite à mes grands-parents.", "Ich besuche meine Großeltern."),
        ("Mon oncle est médecin.", "Mein Onkel ist Arzt."),
        ("Ma tante est professeure.", "Meine Tante ist Lehrerin."),
        ("Nous sommes amis depuis longtemps.", "Wir sind seit langem Freunde."),
        ("Mes grands-parents habitent à la campagne.", "Meine Großeltern wohnen auf dem Land."),
        ("J'aime ma famille.", "Ich liebe meine Familie."),
    ]),
    ("La maison et le logement", [
        ("J'habite dans une maison.", "Ich wohne in einem Haus."),
        ("J'habite dans un appartement.", "Ich wohne in einer Wohnung."),
        ("Ma chambre est grande.", "Mein Zimmer ist groß."),
        ("La cuisine est propre.", "Die Küche ist sauber."),
        ("La salle de bains est petite.", "Das Bad ist klein."),
        ("J'ai un jardin.", "Ich habe einen Garten."),
        ("La clé est sur la table.", "Der Schlüssel ist auf dem Tisch."),
        ("Ferme la porte, s'il te plaît.", "Mach die Tür zu, bitte."),
        ("Ouvre la fenêtre, s'il te plaît.", "Öffne bitte das Fenster."),
        ("Allume la lumière, s'il te plaît.", "Mach bitte das Licht an."),
        ("Éteins la lumière, s'il te plaît.", "Mach bitte das Licht aus."),
        ("Le loyer est trop élevé.", "Die Miete ist zu hoch."),
        ("J'ai besoin d'une serviette.", "Ich brauche ein Handtuch."),
        ("Où est la télévision ?", "Wo ist der Fernseher?"),
        ("Le lit est très confortable.", "Das Bett ist sehr bequem."),
        ("Je nettoie ma chambre.", "Ich räume mein Zimmer auf."),
        ("Le frigo est vide.", "Der Kühlschrank ist leer."),
        ("Le canapé est dans le salon.", "Das Sofa ist im Wohnzimmer."),
        ("Il y a une table dans la cuisine.", "Es gibt einen Tisch in der Küche."),
        ("Ma maison est belle.", "Mein Haus ist schön."),
    ]),
    ("Les repas et la nourriture", [
        ("J'ai faim.", "Ich habe Hunger."),
        ("J'ai soif.", "Ich habe Durst."),
        ("Je mange du pain.", "Ich esse Brot."),
        ("Je bois de l'eau.", "Ich trinke Wasser."),
        ("Je bois du café.", "Ich trinke Kaffee."),
        ("Je mange du riz.", "Ich esse Reis."),
        ("Je n'aime pas le poisson.", "Ich mag keinen Fisch."),
        ("J'aime les fruits.", "Ich mag Obst."),
        ("Le repas est prêt.", "Das Essen ist fertig."),
        ("C'est très bon.", "Das schmeckt sehr gut."),
        ("Je mange à midi.", "Ich esse zu Mittag."),
        ("Je mange le soir à 19h.", "Ich esse am Abend um 19 Uhr."),
        ("Je prépare le dîner.", "Ich koche das Abendessen."),
        ("Je prends le petit-déjeuner.", "Ich frühstücke."),
        ("Passe-moi le sel, s'il te plaît.", "Gib mir bitte das Salz."),
        ("Passe-moi le poivre, s'il te plaît.", "Gib mir bitte den Pfeffer."),
        ("Un verre d'eau, s'il te plaît.", "Ein Glas Wasser, bitte."),
        ("Je suis végétarien.", "Ich bin Vegetarier."),
        ("Je mange de la viande.", "Ich esse Fleisch."),
        ("Le gâteau est délicieux.", "Der Kuchen ist lecker."),
    ]),
    ("Les achats et l'argent", [
        ("Je voudrais acheter ceci.", "Ich möchte das kaufen."),
        ("Combien cela coûte-t-il ?", "Wie viel kostet das?"),
        ("C'est trop cher.", "Das ist zu teuer."),
        ("Avez-vous quelque chose de moins cher ?", "Haben Sie etwas Günstigeres?"),
        ("Où est la caisse ?", "Wo ist die Kasse?"),
        ("Je peux payer par carte ?", "Kann ich mit Karte bezahlen?"),
        ("Je paie en espèces.", "Ich zahle bar."),
        ("Je prends cela.", "Ich nehme das."),
        ("Je cherche une chemise.", "Ich suche ein Hemd."),
        ("Je peux essayer cela ?", "Kann ich das anprobieren?"),
        ("Quelle taille faites-vous ?", "Welche Größe haben Sie?"),
        ("Cela me va bien.", "Das passt mir gut."),
        ("C'est trop grand.", "Das ist zu groß."),
        ("C'est trop petit.", "Das ist zu klein."),
        ("Puis-je avoir un reçu ?", "Kann ich eine Quittung bekommen?"),
        ("J'ai besoin d'argent.", "Ich brauche Geld."),
        ("Où est le distributeur ?", "Wo ist der Geldautomat?"),
        ("Je voudrais retirer de l'argent.", "Ich möchte Geld abheben."),
        ("La carte ne fonctionne pas.", "Die Karte funktioniert nicht."),
        ("C'est gratuit.", "Das ist kostenlos."),
    ]),
    ("Le transport et les déplacements", [
        ("Où est l'arrêt de bus ?", "Wo ist die Bushaltestelle?"),
        ("Quand part le train ?", "Wann fährt der Zug?"),
        ("Un billet pour Berlin, s'il vous plaît.", "Eine Fahrkarte nach Berlin, bitte."),
        ("Où dois-je changer ?", "Wo muss ich umsteigen?"),
        ("Le train a du retard.", "Der Zug hat Verspätung."),
        ("Je prends le bus.", "Ich nehme den Bus."),
        ("Je vais à pied.", "Ich gehe zu Fuß."),
        ("De quel quai part le train ?", "Von welchem Gleis fährt der Zug?"),
        ("Quand arrive le bus ?", "Wann kommt der Bus an?"),
        ("Un aller-retour, s'il vous plaît.", "Einmal hin und zurück, bitte."),
        ("Cette place est-elle libre ?", "Ist dieser Platz frei?"),
        ("Où est l'aéroport ?", "Wo ist der Flughafen?"),
        ("Je voudrais un taxi.", "Ich brauche ein Taxi."),
        ("Combien de temps dure le trajet ?", "Wie lange dauert die Fahrt?"),
        ("Je me suis perdu.", "Ich habe mich verlaufen."),
        ("Je prends le métro.", "Ich nehme die U-Bahn."),
        ("Le bus arrive dans 5 minutes.", "Der Bus kommt in 5 Minuten."),
        ("Où est la gare ?", "Wo ist der Bahnhof?"),
        ("Je vais à l'hôtel.", "Ich gehe zum Hotel."),
        ("Je voyage en train.", "Ich reise mit dem Zug."),
    ]),
    ("À l'hôtel et en voyage", [
        ("J'ai une réservation.", "Ich habe eine Reservierung."),
        ("Je voudrais réserver une chambre.", "Ich möchte ein Zimmer buchen."),
        ("Avez-vous une chambre libre ?", "Haben Sie ein freies Zimmer?"),
        ("À quelle heure est le petit-déjeuner ?", "Wann ist das Frühstück?"),
        ("Où est ma chambre ?", "Wo ist mein Zimmer?"),
        ("La clé ne fonctionne pas.", "Der Schlüssel funktioniert nicht."),
        ("Je reste deux nuits.", "Ich bleibe zwei Nächte."),
        ("Je peux partir plus tard ?", "Kann ich später auschecken?"),
        ("Où puis-je laisser mes bagages ?", "Wo kann ich mein Gepäck lassen?"),
        ("Bon voyage !", "Gute Reise!"),
        ("Le petit-déjeuner est inclus.", "Das Frühstück ist inklusive."),
        ("La chambre est très propre.", "Das Zimmer ist sehr sauber."),
        ("Où est l'ascenseur ?", "Wo ist der Aufzug?"),
        ("Quand dois-je libérer la chambre ?", "Wann muss ich auschecken?"),
        ("J'ai perdu mon passeport.", "Ich habe meinen Pass verloren."),
        ("Ma valise est lourde.", "Mein Koffer ist schwer."),
        ("Je voudrais annuler ma réservation.", "Ich möchte meine Reservierung stornieren."),
        ("Je suis en vacances.", "Ich bin im Urlaub."),
        ("Je voyage pour le travail.", "Ich reise geschäftlich."),
        ("Je visite la ville.", "Ich besichtige die Stadt."),
    ]),
    ("La santé et les urgences", [
        ("Je suis malade.", "Ich bin krank."),
        ("J'ai mal à la tête.", "Ich habe Kopfschmerzen."),
        ("J'ai mal au ventre.", "Ich habe Bauchschmerzen."),
        ("J'ai de la fièvre.", "Ich habe Fieber."),
        ("J'ai mal à la gorge.", "Ich habe Halsschmerzen."),
        ("J'ai besoin d'un médecin.", "Ich brauche einen Arzt."),
        ("Je dois aller chez le médecin.", "Ich muss zum Arzt gehen."),
        ("J'ai besoin d'un rendez-vous.", "Ich brauche einen Termin."),
        ("Où est la pharmacie ?", "Wo ist die Apotheke?"),
        ("J'ai besoin de médicaments.", "Ich brauche Medikamente."),
        ("Au secours !", "Hilfe!"),
        ("Appelez la police !", "Rufen Sie die Polizei!"),
        ("Appelez une ambulance !", "Rufen Sie einen Krankenwagen!"),
        ("C'est une urgence.", "Es ist ein Notfall."),
        ("Je ne me sens pas bien.", "Ich fühle mich nicht gut."),
        ("J'ai mal au dos.", "Mein Rücken tut weh."),
        ("Je suis fatigué.", "Ich bin müde."),
        ("Je me sens mieux.", "Ich fühle mich besser."),
        ("Bon rétablissement !", "Gute Besserung!"),
        ("Je prends ce médicament.", "Ich nehme dieses Medikament."),
    ]),
    ("Le travail et les études", [
        ("Quelle est ta profession ?", "Was machst du beruflich?"),
        ("Je travaille dans un bureau.", "Ich arbeite in einem Büro."),
        ("Je suis étudiant.", "Ich bin Student."),
        ("Je suis à l'école.", "Ich bin in der Schule."),
        ("Je suis un cours d'allemand.", "Ich besuche einen Deutschkurs."),
        ("Le professeur explique la grammaire.", "Der Lehrer erklärt die Grammatik."),
        ("J'ai un examen demain.", "Ich habe morgen eine Prüfung."),
        ("J'ai une question.", "Ich habe eine Frage."),
        ("Je fais mes devoirs.", "Ich mache meine Hausaufgaben."),
        ("J'ai terminé.", "Ich bin fertig."),
        ("Je cherche du travail.", "Ich suche Arbeit."),
        ("Mon chef est sympa.", "Mein Chef ist nett."),
        ("Je suis en congé aujourd'hui.", "Ich habe heute frei."),
        ("J'ai beaucoup de travail.", "Ich habe viel Arbeit."),
        ("Le travail commence à huit heures.", "Die Arbeit beginnt um acht Uhr."),
        ("J'apprends l'allemand pour travailler.", "Ich lerne Deutsch, weil ich arbeiten möchte."),
        ("Je voudrais travailler à Berlin.", "Ich möchte in Berlin arbeiten."),
        ("L'école commence en septembre.", "Die Schule beginnt im September."),
        ("J'étudie à l'université.", "Ich studiere an der Universität."),
        ("Je lis un livre en allemand.", "Ich lese ein Buch auf Deutsch."),
    ]),
    ("Les loisirs et le temps libre", [
        ("Qu'aimes-tu faire ?", "Was machst du gern?"),
        ("J'aime écouter de la musique.", "Ich höre gern Musik."),
        ("J'aime lire.", "Ich lese gern."),
        ("Je joue au football.", "Ich spiele Fußball."),
        ("Je regarde un film.", "Ich sehe einen Film."),
        ("Je vais au cinéma.", "Ich gehe ins Kino."),
        ("Je vais me promener.", "Ich gehe spazieren."),
        ("Je danse.", "Ich tanze."),
        ("Je chante.", "Ich singe."),
        ("Je nage.", "Ich schwimme."),
        ("Je fais du sport.", "Ich mache Sport."),
        ("Je joue de la guitare.", "Ich spiele Gitarre."),
        ("C'est amusant.", "Das macht Spaß."),
        ("Je n'ai pas envie.", "Ich habe keine Lust."),
        ("Allons au parc.", "Lass uns in den Park gehen."),
        ("Tu veux venir avec moi ?", "Möchtest du mitkommen?"),
        ("Avec plaisir !", "Gern!"),
        ("Malheureusement, je ne peux pas.", "Leider kann ich nicht."),
        ("Le week-end, je suis libre.", "Am Wochenende habe ich frei."),
        ("J'ai un passe-temps.", "Ich habe ein Hobby."),
    ]),
    ("La météo et les saisons", [
        ("Quel temps fait-il aujourd'hui ?", "Wie ist das Wetter heute?"),
        ("Il fait beau.", "Das Wetter ist schön."),
        ("Il pleut.", "Es regnet."),
        ("Il neige.", "Es schneit."),
        ("Il fait froid.", "Es ist kalt."),
        ("Il fait chaud.", "Es ist heiß."),
        ("Il y a du vent.", "Es ist windig."),
        ("Le soleil brille.", "Die Sonne scheint."),
        ("Il fait 20 degrés.", "Es sind 20 Grad."),
        ("Prends un parapluie.", "Nimm einen Regenschirm mit."),
        ("En hiver, il fait très froid.", "Im Winter ist es sehr kalt."),
        ("En été, il fait chaud.", "Im Sommer ist es heiß."),
        ("C'est le printemps.", "Es ist Frühling."),
        ("C'est l'automne.", "Es ist Herbst."),
        ("Il fait mauvais.", "Das Wetter ist schlecht."),
        ("Le ciel est bleu.", "Der Himmel ist blau."),
        ("Il y a des nuages.", "Es gibt Wolken."),
        ("Le temps est agréable.", "Das Wetter ist angenehm."),
        ("Il fait nuit.", "Es ist Nacht."),
        ("Demain, il fera beau.", "Morgen wird das Wetter schön."),
    ]),
    ("Les rendez-vous et les projets", [
        ("Qu'est-ce qu'on fait demain ?", "Was machen wir morgen?"),
        ("J'ai un plan.", "Ich habe einen Plan."),
        ("Je voudrais étudier aujourd'hui.", "Ich möchte heute lernen."),
        ("Je t'appellerai.", "Ich werde dich anrufen."),
        ("Peut-être demain.", "Vielleicht morgen."),
        ("On fera cela plus tard.", "Das machen wir später."),
        ("J'ai du temps ce week-end.", "Ich habe am Wochenende Zeit."),
        ("Quand es-tu libre ?", "Wann hast du frei?"),
        ("Je viendrai volontiers.", "Ich komme gern mit."),
        ("À la semaine prochaine !", "Bis nächste Woche!"),
        ("On se retrouve à 18h.", "Wir treffen uns um 18 Uhr."),
        ("Je suis en retard.", "Ich bin zu spät."),
        ("Je suis à l'heure.", "Ich bin pünktlich."),
        ("Je viendrai plus tard.", "Ich komme später."),
        ("On se voit demain.", "Wir sehen uns morgen."),
        ("Je suis occupé aujourd'hui.", "Ich bin heute beschäftigt."),
        ("J'ai un rendez-vous.", "Ich habe einen Termin."),
        ("On se retrouve devant le cinéma.", "Wir treffen uns vor dem Kino."),
        ("À tout à l'heure !", "Bis später!"),
        ("À bientôt !", "Bis bald!"),
    ]),
    ("Les questions et la conversation courante", [
        ("Comment vas-tu ?", "Wie geht es dir?"),
        ("Je vais bien, merci.", "Mir geht es gut, danke."),
        ("Et toi ?", "Und dir?"),
        ("Comment t'appelles-tu ?", "Wie heißt du?"),
        ("Où habites-tu ?", "Wo wohnst du?"),
        ("D'où viens-tu ?", "Woher kommst du?"),
        ("Que fais-tu ?", "Was machst du?"),
        ("Pourquoi ?", "Warum?"),
        ("Quand ?", "Wann?"),
        ("Où ?", "Wo?"),
        ("Qui ?", "Wer?"),
        ("Quoi ?", "Was?"),
        ("Comment ?", "Wie?"),
        ("Combien ?", "Wie viel?"),
        ("Peux-tu m'aider ?", "Kannst du mir helfen?"),
        ("Je ne comprends pas.", "Ich verstehe nicht."),
        ("Peux-tu répéter ?", "Kannst du das wiederholen?"),
        ("Plus lentement, s'il te plaît.", "Langsamer, bitte."),
        ("Comment dit-on cela en allemand ?", "Wie sagt man das auf Deutsch?"),
        ("Merci beaucoup.", "Vielen Dank."),
    ]),
]

def seed_speak_phrases(cursor):
    for theme_order, (theme, items) in enumerate(SPEAK_PHRASES_DATA, start=1):
        for fr, de in items:
            cursor.execute(
                "INSERT OR IGNORE INTO speak_phrases(theme, theme_order, fr, de) VALUES(?,?,?,?)",
                (theme, theme_order, fr, de)
            )

# =========================================================
# === AJOUT : SEED "LES ESSENTIELS A1" (24 fiches + explications) ===
# =========================================================
ESSENTIALS_DATA = [
    (1, "Les pronoms personnels (sujets)",
     "Je = ich\nTu = du\nIl = er\nElle = sie\nIl/Elle (neutre) = es\nNous = wir\nVous (pluriel) = ihr\nVous (poli) = Sie\nIls/Elles = sie",
     "Le pronom sujet se place toujours avant le verbe. 'Sie' avec majuscule = vouvoiement ; 'sie' minuscule = ils/elles."),
    (2, "Le verbe 'sein' (être) au présent",
     "Je suis = ich bin\nTu es = du bist\nIl/Elle est = er/sie/es ist\nNous sommes = wir sind\nVous êtes = ihr seid\nIls/Elles sont = sie sind\nVous êtes (poli) = Sie sind",
     "'sein' est irrégulier : il faut le mémoriser. C'est le verbe le plus utilisé en allemand."),
    (3, "Le verbe 'haben' (avoir) au présent",
     "J'ai = ich habe\nTu as = du hast\nIl/Elle a = er/sie/es hat\nNous avons = wir haben\nVous avez = ihr habt\nIls/Elles ont = sie haben\nVous avez (poli) = Sie haben",
     "'haben' est aussi irrégulier au singulier (du hast, er hat). Indispensable pour parler."),
    (4, "Les articles définis (le, la, les)",
     "Masculin : der (ex: der Mann)\nFéminin : die (ex: die Frau)\nNeutre : das (ex: das Kind)\nPluriel : die (ex: die Kinder)",
     "Il existe 3 genres en allemand. Le pluriel est toujours 'die'. Apprends toujours le nom AVEC son article."),
    (5, "Les articles indéfinis (un, une)",
     "Masculin : ein (ex: ein Mann)\nFéminin : eine (ex: eine Frau)\nNeutre : ein (ex: ein Kind)",
     "'ein' pour masculin et neutre, 'eine' pour féminin. Pas d'article indéfini au pluriel."),
    (6, "Les questions avec 'W'",
     "Qui ? = Wer?\nQuoi ? = Was?\nOù ? = Wo?\nD'où ? = Woher?\nOù (direction) ? = Wohin?\nQuand ? = Wann?\nPourquoi ? = Warum?\nComment ? = Wie?",
     "Les mots interrogatifs allemands commencent presque tous par W. Le verbe reste en 2e position."),
    (7, "La négation",
     "Ne pas = nicht (ex: Ich verstehe nicht. = Je ne comprends pas.)\nAucun/Ne...pas de = kein/keine (ex: Ich habe keinen Hund. = Je n'ai pas de chien.)",
     "'nicht' nie un verbe/adj. 'kein' nie un nom (avec l'article indéfini)."),
    (8, "Les verbes réguliers au présent (exemple: lernen)",
     "J'apprends = ich lerne\nTu apprends = du lernst\nIl/Elle apprend = er/sie/es lernt\nNous apprenons = wir lernen\nVous apprenez = ihr lernt\nIls/Elles apprennent = sie lernen",
     "Verbes réguliers : radical + terminaison (-e, -st, -t, -en, -t, -en)."), 
    (9, "Les verbes irréguliers courants au présent",
     "Je parle = ich spreche\nTu parles = du sprichst\nIl/Elle parle = er/sie/es spricht\nJe lis = ich lese\nTu lis = du liest\nIl/Elle lit = er/sie/es liest\nJe mange = ich esse\nTu manges = du isst\nIl/Elle mange = er/sie/es isst",
     "Certains verbes changent de voyelle au singulier (e → i, a → ä). Il faut les mémoriser."),
    (10, "Les nombres de 0 à 20",
     "0 null, 1 eins, 2 zwei, 3 drei, 4 vier, 5 fünf, 6 sechs, 7 sieben, 8 acht, 9 neun, 10 zehn, 11 elf, 12 zwölf, 13 dreizehn, 14 vierzehn, 15 fünfzehn, 16 sechzehn, 17 siebzehn, 18 achtzehn, 19 neunzehn, 20 zwanzig.",
     "À partir de 13, on ajoute 'zehn' au chiffre de base. 6 = sechs, 7 = sieben (attention à l'orthographe)."),
    (11, "Les jours de la semaine",
     "Lundi = Montag\nMardi = Dienstag\nMercredi = Mittwoch\nJeudi = Donnerstag\nVendredi = Freitag\nSamedi = Samstag\nDimanche = Sonntag",
     "Tous les jours se terminent par '-tag' sauf Mittwoch. Toujours avec une majuscule en allemand."),
    (12, "Les mois de l'année",
     "Janvier = Januar\nFévrier = Februar\nMars = März\nAvril = April\nMai = Mai\nJuin = Juni\nJuillet = Juli\nAoût = August\nSeptembre = September\nOctobre = Oktober\nNovembre = November\nDécembre = Dezember",
     "Presque identiques au français sauf Januar, Februar, März, Juni, Juli. Majuscule obligatoire."),
    (13, "Les couleurs",
     "Rouge = rot\nBleu = blau\nVert = grün\nJaune = gelb\nNoir = schwarz\nBlanc = weiß\nGris = grau\nMarron = braun\nRose = rosa",
     "Les couleurs sont des adjectifs. Elles se placent avant le nom et prennent une terminaison."),
    (14, "Les salutations",
     "Bonjour = Guten Tag\nBonjour (matin) = Guten Morgen\nBonsoir = Guten Abend\nBonne nuit = Gute Nacht\nSalut = Hallo\nAu revoir = Auf Wiedersehen\nÀ bientôt = Bis bald\nÀ demain = Bis morgen",
     "'Guten' change en 'Gute' devant Nacht (féminin). Utilise 'Hallo' entre amis, 'Guten Tag' en formel."),
    (15, "Les formules de politesse",
     "Merci = Danke\nMerci beaucoup = Vielen Dank\nS'il te plaît / Je t'en prie = Bitte\nExcusez-moi = Entschuldigung\nPardon = Verzeihung\nJe suis désolé = Es tut mir leid\nPas de problème = Kein Problem",
     "'Bitte' a plusieurs sens : s'il te plaît, je t'en prie, de rien. Indispensable."),
    (16, "Les mots de temps",
     "Aujourd'hui = heute\nDemain = morgen\nHier = gestern\nMaintenant = jetzt\nPlus tard = später\nToujours = immer\nJamais = nie\nSouvent = oft\nParfois = manchmal",
     "Ces adverbes se placent en général après le verbe. 'nie' est l'opposé de 'immer'."),
    (17, "Les adverbes de lieu",
     "Ici = hier\nLà-bas = dort\nÀ gauche = links\nÀ droite = rechts\nTout droit = geradeaus\nEn haut = oben\nEn bas = unten\nDevant = vorne\nDerrière = hinten",
     "Très utiles pour demander le chemin : 'links', 'rechts', 'geradeaus'."),
    (18, "Les verbes de base (infinitif)",
     "Être = sein\nAvoir = haben\nFaire = machen\nAller = gehen\nVenir = kommen\nManger = essen\nBoire = trinken\nDormir = schlafen\nLire = lesen\nÉcrire = schreiben\nParler = sprechen\nÉcouter = hören\nVoir = sehen\nAcheter = kaufen\nTravailler = arbeiten\nHabiter = wohnen\nJouer = spielen\nConduire = fahren\nAttendre = warten\nAider = helfen",
     "À l'infinitif, les verbes se terminent en '-en' ou '-n'. Base de tout le vocabulaire."),
    (19, "Les adjectifs courants",
     "Grand = groß\nPetit = klein\nLong = lang\nCourt = kurz\nVieux = alt\nNouveau = neu\nJeune = jung\nBon = gut\nMauvais = schlecht\nBeau = schön\nChaud = heiß\nFroid = kalt\nRapide = schnell\nLent = langsam\nCher = teuer\nBon marché = billig",
     "Pour les adjectifs, apprends aussi la forme de base sans terminaison."),
    (20, "Les prépositions de lieu",
     "Dans = in\nSur = auf\nSous = unter\nÀ côté de = neben\nDevant = vor\nDerrière = hinter\nEntre = zwischen\nÀ = zu\nAvec = mit\nSans = ohne",
     "Attention : 'in' + datif pour la position, 'in' + accusatif pour la direction."),
    (21, "La structure d'une phrase simple",
     "Sujet + Verbe + Complément.\nExemple : Ich lerne heute Deutsch.\n(Je + apprends + aujourd'hui + l'allemand)",
     "Le verbe est toujours en deuxième position dans une phrase simple. Règle absolue."),
    (22, "Les possessifs (mon, ton, son...)",
     "Mon (masculin) = mein (ex: mein Vater)\nMa (féminin) = meine (ex: meine Mutter)\nMes (pluriel) = meine (ex: meine Eltern)\nTon (masculin) = dein (ex: dein Bruder)\nTa (féminin) = deine (ex: deine Schwester)",
     "'mein' / 'dein' au masculin-neutre. 'meine' / 'deine' au féminin et au pluriel."),
    (23, "Les nombres de 20 à 100",
     "Vingt = zwanzig\nTrente = dreißig\nQuarante = vierzig\nCinquante = fünfzig\nSoixante = sechzig\nSoixante-dix = siebzig\nQuatre-vingts = achtzig\nQuatre-vingt-dix = neunzig\nCent = hundert",
     "Après 20, on ajoute '-zig' sauf trente = dreißig (avec ß)."),
    (24, "Les phrases utiles pour l'examen",
     "Je m'appelle... = Ich heiße...\nJ'habite à... = Ich wohne in...\nJe viens de... = Ich komme aus...\nJ'ai... ans = Ich bin... Jahre alt\nJe parle... = Ich spreche...\nJe ne comprends pas = Ich verstehe nicht\nPouvez-vous répéter ? = Können Sie das wiederholen?\nComment dit-on... en allemand ? = Wie sagt man... auf Deutsch?",
     "Ces 8 phrases suffisent pour réussir la partie Sprechen de l'examen A1."),
]

def seed_essentials_cards(cursor):
    for num, title, content, explanation in ESSENTIALS_DATA:
        cursor.execute(
            "INSERT OR IGNORE INTO essentials_cards(fiche_num, title, content, explanation) VALUES(?,?,?,?)",
            (num, title, content, explanation)
        )

# =========================================================
# === AJOUT : Playlists séparées (idempotent) ===
# =========================================================
def seed_speak_playlists(cursor):
    # Playlist "Apprendre à parler" par thème
    for theme_order, (theme, items) in enumerate(SPEAK_PHRASES_DATA, start=1):
        payload = json.dumps([{"fr": fr, "de": de} for fr, de in items], ensure_ascii=False)
        cursor.execute(
            "INSERT OR IGNORE INTO speak_playlists(kind, key, title, items_json) VALUES(?,?,?,?)",
            ("speak", theme, theme, payload)
        )
    # Playlist "Essentiels A1" (une seule playlist avec toutes les fiches lues)
    essentials_items = []
    for num, title, content, explanation in ESSENTIALS_DATA:
        # On lit le titre puis chaque ligne français → allemand
        # Ici, on lit simplement la fiche en allemand (contenu condensé)
        for line in content.split("\n"):
            if "=" in line:
                left, right = line.split("=", 1)
                essentials_items.append({
                    "fr": left.strip() + " : " + right.strip(),
                    "de": right.strip()
                })
    payload = json.dumps(essentials_items, ensure_ascii=False)
    cursor.execute(
        "INSERT OR IGNORE INTO speak_playlists(kind, key, title, items_json) VALUES(?,?,?,?)",
        ("essentials", "all", "Les essentiels A1", payload)
    )

# ---------------------------------------------------------
# SÉCURITÉ & DÉCORATEURS
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
# HELPERS
# ---------------------------------------------------------
def say_btn(label, mode, fr="", de="", css="btn", style=""):
    style_attr = f' style="{h(style, quote=True)}"' if style else ""
    return (f'<button type="button" class="{css}" data-say="{mode}" '
            f'data-fr="{h(fr, quote=True)}" data-de="{h(de, quote=True)}"{style_attr}>{label}</button>')

def playlist_btn(label, kind, key, css="btn"):
    return (f'<button type="button" class="{css}" data-say="playlist" '
            f'data-kind="{h(kind, quote=True)}" data-key="{h(key, quote=True)}">{label}</button>')

# ---------------------------------------------------------
# CSS & JS
# ---------------------------------------------------------
FAVICON_SVG = """data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%2387CEEB'/><path d='M30 65V45c0-15 10-25 20-25s20 10 20 25v20' stroke='white' stroke-width='8' fill='none' stroke-linecap='round'/><rect x='25' y='60' width='12' height='20' rx='4' fill='white'/><rect x='63' y='60' width='12' height='20' rx='4' fill='white'/><text x='50' y='58' font-family='Arial' font-size='28' font-weight='bold' fill='white' text-anchor='middle'>N</text></svg>"""

# === AJOUT : variables CSS mode nuit ===
BASE_CSS = """
<style>
:root{
  --sky:#87CEEB; --sky-dark:#4AA5D0; --sky-light:#E8F6FD;
  --ink:#0F2A3F; --muted:#5B7A90; --white:#FFFFFF;
  --ok:#2ECC71; --warn:#F39C12; --danger:#E74C3C;
  --bg-gradient: linear-gradient(180deg,#E8F6FD 0%,#F7FCFE 100%);
  --card-bg: #FFFFFF;
  --nav-bg: #87CEEB;
  --sidebar-bg: #1a2a35;
  --input-bg: #fbfdff;
  --border-light: #EAF3F8;
}
html[data-theme="dark"]{
  --sky:#4AA5D0; --sky-dark:#2F8CBB; --sky-light:#1e3a4d;
  --ink:#E8F6FD; --muted:#9BB8C9; --white:#0F2A3F;
  --bg-gradient: linear-gradient(180deg,#0F2A3F 0%,#152F44 100%);
  --card-bg: #16304a;
  --nav-bg: #0d2233;
  --sidebar-bg: #071722;
  --input-bg: #1a3a52;
  --border-light: #1f4560;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,Arial,sans-serif;
     background:var(--bg-gradient);
     color:var(--ink);min-height:100vh; padding-bottom: 90px; margin-left: 200px; transition: margin-left 0.3s, background 0.3s, color 0.3s;}
body.no-sidebar { margin-left: 0; }
.nav{background:var(--nav-bg);color:white;padding:14px 22px;
     display:flex;justify-content:space-between;align-items:center;
     box-shadow:0 2px 8px rgba(0,0,0,.08);position:sticky;top:0;z-index:50; margin-left: -200px; transition: margin-left 0.3s, background 0.3s;}
body.no-sidebar .nav { margin-left: 0; }
.nav .brand{font-weight:800;font-size:22px;letter-spacing:1px;display:flex;align-items:center;gap:10px}
.nav a{color:white;text-decoration:none;margin-left:16px;font-weight:500;opacity:.95}
.nav a:hover{opacity:1;text-decoration:underline}
.container{max-width:1100px;margin:0 auto;padding:24px 18px 60px}
.card{background:var(--card-bg);border-radius:16px;padding:22px;
      box-shadow:0 6px 22px rgba(74,165,208,.12);margin-bottom:18px; transition: background 0.3s;}
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
     transition:.2s;background:var(--input-bg);color:var(--ink)}
input:focus,select:focus,textarea:focus{border-color:var(--sky-dark)}
label{font-weight:600;font-size:14px;color:var(--muted)}
.flash{padding:12px 16px;border-radius:10px;margin-bottom:14px;font-weight:500}
.flash.success{background:#D4F5E3;color:#1E7A45}
.flash.danger{background:#FBE1DE;color:#A02A1B}
.flash.warning{background:#FFF1D6;color:#8A5C00}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px}
.lesson{background:var(--card-bg);border-radius:14px;padding:16px;
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
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--border-light)}
th{background:var(--sky-light);font-weight:700;color:var(--ink)}
.hero{background:linear-gradient(135deg,var(--sky),#B8E2F5);color:white;
      border-radius:22px;padding:40px 30px;text-align:center;margin-bottom:22px}
.hero h1{color:white;font-size:32px}
.hero p{opacity:.95;margin:10px 0 22px;font-size:16px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px}
.stat{background:var(--card-bg);border-radius:14px;padding:18px;text-align:center;
      box-shadow:0 4px 14px rgba(74,165,208,.10)}
.stat .num{font-size:28px;font-weight:800;color:var(--sky-dark)}
.stat .lbl{font-size:13px;color:var(--muted);margin-top:4px}
.quiz-opt{display:block;background:var(--card-bg);border:2px solid var(--sky-light);
      border-radius:10px;padding:13px 16px;margin:8px 0;cursor:pointer;transition:.15s}
.quiz-opt:hover{border-color:var(--sky-dark)}
.quiz-opt input{margin-right:10px;width:auto}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.tabs a{padding:8px 16px;border-radius:20px;background:var(--card-bg);text-decoration:none;
      font-size:13px;font-weight:600;color:var(--muted);border:2px solid var(--sky-light)}
.tabs a.active{background:var(--sky-dark);color:white;border-color:var(--sky-dark)}
footer{text-align:center;padding:24px;color:var(--muted);font-size:13px}
footer a { color: var(--muted); text-decoration: underline; margin: 0 10px;}

/* --- SIDEBAR (Niveaux) --- */
.sidebar {
  position: fixed; top: 0; left: 0; bottom: 0; width: 200px;
  background: var(--sidebar-bg); color: white; padding: 20px 15px; z-index: 60;
  display: flex; flex-direction: column; gap: 20px;
}
.sidebar h3 { color: #87CEEB; font-size: 14px; text-transform: uppercase; margin-bottom: 10px; letter-spacing: 1px;}
.sidebar .level { padding: 10px; border-radius: 8px; background: rgba(255,255,255,0.05); margin-bottom: 8px; cursor: not-allowed; opacity: 0.6;}
.sidebar .level .tag { font-size: 10px; background: #E74C3C; padding: 2px 6px; border-radius: 4px; float: right; font-weight: bold;}
.sidebar .level.active { background: #4AA5D0; opacity: 1; cursor: pointer;}
.sidebar .level.active .tag { display: none;}

/* === AJOUT : bouton menu mobile (3 points / hamburger) === */
.mobile-menu-btn {
  display: none;
  background: rgba(255,255,255,0.2);
  color: white;
  border: none;
  font-size: 22px;
  width: 42px; height: 42px;
  border-radius: 10px;
  cursor: pointer;
  margin-left: 8px;
}
.mobile-menu-btn:hover { background: rgba(255,255,255,0.35); }

/* === AJOUT : drawer mobile === */
.mobile-drawer {
  position: fixed; top: 0; right: -280px; bottom: 0; width: 280px;
  background: var(--sidebar-bg); color: white;
  z-index: 200; padding: 20px; transition: right 0.3s ease;
  box-shadow: -4px 0 20px rgba(0,0,0,0.3);
}
.mobile-drawer.open { right: 0; }
.mobile-drawer h3 { color: #87CEEB; font-size: 13px; text-transform: uppercase; margin-bottom: 12px; }
.mobile-drawer .close-x {
  position: absolute; top: 12px; right: 14px; background: none; border: none;
  color: white; font-size: 24px; cursor: pointer;
}
.mobile-drawer .level { padding: 12px; border-radius: 8px; background: rgba(255,255,255,0.06); margin-bottom: 10px; opacity: 0.7;}
.mobile-drawer .level.active { background: #4AA5D0; opacity: 1;}
.mobile-drawer .level .tag { font-size: 10px; background: #E74C3C; padding: 2px 6px; border-radius: 4px; float: right; font-weight: bold;}
.mobile-drawer .level.active .tag { display: none;}

/* === AJOUT : bouton mode nuit === */
.theme-toggle {
  background: rgba(255,255,255,0.2);
  color: white;
  border: none;
  padding: 8px 12px;
  border-radius: 8px;
  cursor: pointer;
  font-size: 14px;
  margin-left: 8px;
}
.theme-toggle:hover { background: rgba(255,255,255,0.35); }

@media (max-width: 800px) {
  body { margin-left: 0; }
  .nav { margin-left: 0; padding: 10px 15px; flex-direction: row; align-items: center; gap: 8px; flex-wrap: wrap;}
  .nav .brand { font-size: 16px; }
  .nav > div:nth-child(2) { display: flex; flex-wrap: wrap; gap: 8px; margin-left: 0; width: 100%;}
  .nav a { margin-left: 0; font-size: 12px; }
  .sidebar { display: none; }
  .mobile-menu-btn { display: inline-block; }
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

/* --- ESSENTIELS : style des fiches --- */
.fiche { background: var(--card-bg); border-radius: 14px; padding: 18px; margin-bottom: 14px; border-left: 5px solid var(--sky); }
.fiche h3 { color: var(--sky-dark); font-size: 16px; margin-bottom: 10px; }
.fiche .content { font-family: 'Courier New', monospace; background: var(--input-bg); padding: 12px; border-radius: 8px; font-size: 13px; white-space: pre-wrap; line-height: 1.6; color: var(--ink); }
.fiche .explanation { margin-top: 10px; font-size: 13px; color: var(--muted); font-style: italic; padding: 10px; background: rgba(135,206,235,0.12); border-radius: 8px; }
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
    if (kind === 'speak' || kind === 'essentials') {
      return d[kind] && d[kind][key];
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

# === AJOUT : JS pour le mode nuit + menu mobile ===
THEME_MOBILE_JS = r"""
<script>
(function(){
  // Mode nuit
  function applyTheme(t){
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('natho_theme', t); } catch(e){}
    var btns = document.querySelectorAll('.theme-toggle');
    btns.forEach(function(b){ b.textContent = t === 'dark' ? '☀️' : '🌙'; });
  }
  window.toggleTheme = function(){
    var cur = document.documentElement.getAttribute('data-theme') || 'light';
    applyTheme(cur === 'dark' ? 'light' : 'dark');
  };
  var saved = null;
  try { saved = localStorage.getItem('natho_theme'); } catch(e){}
  applyTheme(saved === 'dark' ? 'dark' : 'light');

  // Drawer mobile
  window.openMobileMenu = function(){
    var d = document.getElementById('mobile-drawer');
    if (d) d.classList.add('open');
  };
  window.closeMobileMenu = function(){
    var d = document.getElementById('mobile-drawer');
    if (d) d.classList.remove('open');
  };
})();
</script>
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
            <a href="{url_for('apprendre_parler')}">Parler 🗨️</a>
            <a href="{url_for('essentiels_a1')}">Essentiels A1</a>
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

    # === AJOUT : bouton theme + menu mobile dans la nav ===
    theme_btn = '<button class="theme-toggle" onclick="toggleTheme()" title="Mode nuit">🌙</button>'
    mobile_btn = '<button class="mobile-menu-btn" onclick="openMobileMenu()" title="Menu">☰</button>'

    # === AJOUT : drawer mobile ===
    mobile_drawer = ""
    if show_sidebar:
        mobile_drawer = """
        <div class="mobile-drawer" id="mobile-drawer">
            <button class="close-x" onclick="closeMobileMenu()">×</button>
            <h3>Niveaux</h3>
            <div class="level active"><strong>A1</strong> <span style="font-size:11px;display:block;">Actuel</span></div>
            <div class="level"><strong>A2</strong> <span class="tag">Bientôt</span><span style="font-size:11px;display:block;margin-top:4px;">Élémentaire</span></div>
            <div class="level"><strong>B1</strong> <span class="tag">Bientôt</span><span style="font-size:11px;display:block;margin-top:4px;">Intermédiaire</span></div>
            <div class="level"><strong>B2</strong> <span class="tag">Bientôt</span><span style="font-size:11px;display:block;margin-top:4px;">Avancé</span></div>
        </div>
        """

    return f"""
<!doctype html><html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NATHO — {title}</title>
<link rel="icon" type="image/svg+xml" href="{FAVICON_SVG}">
{BASE_CSS}
</head><body class="{body_class}">

{sidebar_html}
{mobile_drawer}

<div class="nav">
  <div class="brand"><img src="{FAVICON_SVG}" width="28" height="28" style="border-radius:6px;"> NATHO · Deutsch A1</div>
  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">{nav_links} {theme_btn} {mobile_btn}</div>
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
    © NATHO — Plateforme d'apprentissage de l'allemand A1 · Prototype v4.0<br>
    <a href="/politique">Politique de confidentialité</a> | 
    <a href="/cgu">Conditions d'utilisation</a> | 
    <a href="/mentions">Mentions légales</a>
</footer>
<script>window.NATHO_TTS = {'true' if TTS_OK else 'false'};</script>
<script>{{% raw %}}{AUDIO_JS}{{% endraw %}}</script>
{THEME_MOBILE_JS}
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
        <div class="card"><h3>🗨️ Apprendre à parler</h3><p>260 phrases complètes classées par thème : Sujet + Verbe + Complément.</p></div>
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
                <div style="font-size:16px; font-weight:bold; color:#0F2A3F;">{l['de']}</div>
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

# =========================================================
# === AJOUT : ROUTE "APPRENDRE À PARLER" ===
# =========================================================
@app.route("/apprendre-parler")
@login_required
def apprendre_parler():
    db = get_db()
    rows = db.execute(
        "SELECT theme, theme_order, fr, de FROM speak_phrases ORDER BY theme_order, id"
    ).fetchall()

    # Regrouper par thème
    themes = {}
    for r in rows:
        themes.setdefault((r["theme_order"], r["theme"]), []).append(r)

    tabs = ""
    sections = ""
    first = True
    for (order, theme_name), items in sorted(themes.items()):
        active = "active" if first else ""
        tabs += f'<a href="#theme-{order}" class="{active}" onclick="document.querySelectorAll(\'.tabs a\').forEach(a=>a.classList.remove(\'active\'));this.classList.add(\'active\');">{theme_name}</a>'
        cards = ""
        for it in items:
            cards += f"""
            <div class="lesson">
              <div class="de">{it['de']}</div>
              <div class="fr">{it['fr']}</div>
              <div class="actions">
                {say_btn("▶ Écouter", "pair", it['fr'], it['de'])}
                {say_btn("🔊 Allemand", "de", it['fr'], it['de'], css="btn ghost")}
              </div>
            </div>"""
        playlist = playlist_btn("▶ Playlist de ce thème", "speak", theme_name, css="btn ok")
        sections += f"""
        <div id="theme-{order}" style="margin-top:24px;">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px;">
            <h2 style="margin:0;">{theme_name}</h2>
            {playlist}
          </div>
          <div class="grid">{cards}</div>
        </div>"""
        first = False

    n = len(rows)
    body = f"""
    <h1>Apprendre à parler 🗨️</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">
      {n} phrases complètes classées par thème, construites sur le modèle <b>Sujet + Verbe + Complément</b>.
      Chaque phrase est lue en français puis en allemand (lentement). Utilise les playlists pour tout enchaîner.
    </p>
    <div class="tabs">{tabs}</div>
    {sections}
    """
    return render_template_string(layout("Apprendre à parler", body, {"is_admin": session.get("is_admin")}))

# =========================================================
# === AJOUT : ROUTE "LES ESSENTIELS A1" ===
# =========================================================
@app.route("/essentiels-a1")
@login_required
def essentiels_a1():
    db = get_db()
    fiches = db.execute(
        "SELECT * FROM essentials_cards ORDER BY fiche_num"
    ).fetchall()

    cards_html = ""
    for f in fiches:
        # Générer un bouton audio par ligne "fr = de"
        audio_lines = ""
        for line in f["content"].split("\n"):
            line = line.strip()
            if "=" in line:
                left, right = line.split("=", 1)
                fr_part = left.strip()
                de_part = right.strip()
                audio_lines += f"""
                <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px dashed var(--border-light);gap:8px;">
                  <div style="flex:1;font-size:13px;"><b>{h(de_part)}</b> <span style="color:var(--muted);">— {h(fr_part)}</span></div>
                  {say_btn("▶", "pair", fr_part, de_part, css="btn ghost", style="padding:4px 10px;font-size:12px;")}
                </div>
                """
        cards_html += f"""
        <div class="fiche">
          <h3>Fiche {f['fiche_num']} — {h(f['title'])}</h3>
          <div class="content">{audio_lines if audio_lines else h(f['content'])}</div>
          <div class="explanation">💡 {h(f['explanation'])}</div>
        </div>
        """

    playlist_all = playlist_btn("▶ Playlist : toutes les fiches", "essentials", "all", css="btn ok")

    body = f"""
    <h1>Les essentiels A1 📌</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">
      24 fiches de révision condensées pour réussir l'examen Goethe A1. Chaque fiche contient l'essentiel + une explication pédagogique.
    </p>
    <div class="card" style="display:flex;justify-content:space-between;align-items:center;">
      <div>
        <h3 style="margin:0">Écouter toutes les fiches</h3>
        <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0;">Toutes les paires français → allemand lues à la suite.</p>
      </div>
      {playlist_all}
    </div>
    {cards_html}
    """
    return render_template_string(layout("Les essentiels A1", body, {"is_admin": session.get("is_admin")}))

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

    # === AJOUT : playlists "speak" et "essentials" ===
    playlist_data_speak = {}
    speak_rows = db.execute("SELECT key, title, items_json FROM speak_playlists WHERE kind='speak'").fetchall()
    for r in speak_rows:
        playlist_data_speak[r["title"]] = json.loads(r["items_json"])

    playlist_data_essentials = {}
    ess_rows = db.execute("SELECT key, title, items_json FROM speak_playlists WHERE kind='essentials'").fetchall()
    for r in ess_rows:
        playlist_data_essentials[r["title"]] = json.loads(r["items_json"])

    order_l = [r["category"] for r in db.execute(
        "SELECT category FROM lessons GROUP BY category ORDER BY MIN(order_index), MIN(id)").fetchall()]
    order_v = [r["category"] for r in db.execute(
        "SELECT category FROM vocab GROUP BY category ORDER BY MIN(id)").fetchall()]
    order_d = [r["title"] for r in d_rows]

    n_lessons = sum(len(v) for v in playlist_data_lessons.values())
    n_vocab = sum(len(v) for v in playlist_data_vocab.values())
    n_dialogues = sum(len(v) for v in playlist_data_dialogues.values())
    n_numbers = len(playlist_data_numbers["Nombres 0-1000"])
    n_speak = sum(len(v) for v in playlist_data_speak.values())
    n_ess = sum(len(v) for v in playlist_data_essentials.values())

    js_data = json.dumps({
        "lessons": playlist_data_lessons,
        "vocab": playlist_data_vocab,
        "dialogues": playlist_data_dialogues,
        "numbers": playlist_data_numbers,
        "speak": playlist_data_speak,
        "essentials": playlist_data_essentials,
        "order": {"lessons": order_l, "vocab": order_v, "dialogues": order_d}
    }, ensure_ascii=False).replace("</", "<\\/")

    cards_all = f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Tous les cours</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{n_lessons} phrases en un seul bloc.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "lessons", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Tout le vocabulaire</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{n_vocab} mots en un seul bloc.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "vocab", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Tous les dialogues</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{n_dialogues} répliques (50 dialogues).</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "dialogues", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">Les nombres 0 à 1000</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{n_numbers} nombres lus à la suite.</p>
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

    # === AJOUT : section Playlists "Apprendre à parler" ===
    cards_speak = ""
    for theme_title, items in playlist_data_speak.items():
        cards_speak += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{h(theme_title)}</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{len(items)} phrases complètes.</p>
            </div>
            {playlist_btn("▶ Playlist", "speak", theme_title, css="btn ok")}
        </div>
        """

    # === AJOUT : section Playlist "Essentiels A1" ===
    cards_ess = ""
    for title, items in playlist_data_essentials.items():
        cards_ess += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{h(title)}</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{len(items)} paires FR → DE.</p>
            </div>
            {playlist_btn("▶ Playlist", "essentials", title, css="btn ok")}
        </div>
        """

    cards_lessons = ""
    for c in cats_lessons:
        cards_lessons += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{c['category']}</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">Leçons de cours.</p>
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
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">Mots de vocabulaire.</p>
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
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">Dialogue.</p>
            </div>
            {playlist_btn("▶ Playlist", "dialogues", c, css="btn")}
        </div>
        """

    body = f"""
    <h1>Playlists Audio 🎵</h1>
    <p style="margin-bottom:20px;color:var(--muted);">Le mode Spotify de NATHO. Choisis ce que tu veux écouter.</p>

    <h2>🎧 Blocs complets</h2>
    {cards_all}

    <h2 style="margin-top:30px;">🗨️ Apprendre à parler (par thème)</h2>
    {cards_speak}

    <h2 style="margin-top:30px;">📌 Essentiels A1</h2>
    {cards_ess}

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
# PAGES LÉGALES
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
        <p>Nous utilisons des cookies pour :<br>- Maintenir votre session connectée.<br>- Mémoriser vos préférences audio.<br>- Sauvegarder votre progression.</p>
        <h2>3. Sécurité</h2>
        <p>Les mots de passe sont chiffrés. Nous vous recommandons d'utiliser un mot de passe fort.</p>
        <h2>4. Vos droits</h2>
        <p>Conformément au RGPD, vous pouvez demander la suppression de votre compte à tout moment.</p>
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
        <h2>2. Propriété intellectuelle</h2>
        <p>L'ensemble du contenu est la propriété exclusive de NATHO. <strong>Toute reproduction non autorisée est strictement interdite.</strong></p>
        <h2>3. Utilisation</h2>
        <p>Vous vous engagez à ne pas partager vos identifiants de connexion.</p>
        <h2>4. Responsabilité</h2>
        <p>NATHO ne délivre pas de certificat officiel Goethe. Les examens proposés sont des simulations.</p>
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
    {"audio": "Ich suche die Toilette.", "q": "Que cherche la personne ?", "opts": ["Les toilettes", "La sortie", "L'entrée"], "ans": "0"}
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
    {"text": "Ich habe zwei Kinder, einen Jungen und ein Mädchen.", "q": "Combien d'enfants a la personne ?", "opts": ["Deux", "Un", "Trois"], "ans": "0"}
]

SCHREIBEN_QUESTIONS = [
    {"q": "Écris un message à un ami pour l'inviter à dîner ce soir. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour dire que tu es malade et que tu ne peux pas venir au cours. (Hallo, ...)", "min_words": 5},
    {"q": "Écris un message pour demander le prix d'un billet de train pour Munich. (Guten Tag, ...)", "min_words": 5},
    {"q": "Écris un message pour t'excuser d'être en retard au rendez-vous. (Entschuldigung, ...)", "min_words": 5},
    {"q": "Écris un message pour remercier ton ami pour le cadeau. (Liebe/r ..., ...)", "min_words": 5}
]

SPRECHEN_QUESTIONS = [
    {"q": "Présente-toi : Dis ton nom, ton pays, ta ville et ta langue maternelle.", "example": "Hallo! Ich heiße Thomas. Ich komme aus Kamerun. Ich wohne in Douala. Ich lerne Deutsch."},
    {"q": "Épelle ton nom de famille lentement à voix haute.", "example": "M-A-R-T-I-N"},
    {"q": "Dis à voix haute que tu aimes le café et que tu n'aimes pas le thé.", "example": "Ich mag Kaffee, aber ich mag keinen Tee."},
    {"q": "Dis les jours de la semaine en allemand.", "example": "Montag, Dienstag, Mittwoch, Donnerstag, Freitag, Samstag, Sonntag."},
    {"q": "Commande un café et un croissant dans un restaurant à voix haute.", "example": "Ich hätte gern einen Kaffee und ein Croissant."}
]

@app.route("/goethe")
@login_required
def goethe():
    body = """
    <h1>Examen Goethe A1 (Simulateur)</h1>
    <p style="margin-bottom:20px;color:var(--muted);">Cet examen blanc est structuré en 4 modules officiels. Il ne délivre pas de certificat officiel, mais il te prépare parfaitement aux conditions réelles.</p>

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
      <div style="background:var(--sky-light);padding:16px;border-radius:10px;margin:14px 0;">
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
      <div style="background:var(--sky-light);padding:16px;border-radius:10px;margin:14px 0;font-style:italic;">
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
          <p style="color:var(--muted);margin-top:10px;">Note : dans un vrai examen, un correcteur humain évalue la grammaire et le vocabulaire.</p>
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
      <div style="background:var(--sky-light);padding:16px;border-radius:10px;margin:14px 0;">
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
    speak_count = db.execute("SELECT COUNT(*) FROM speak_phrases").fetchone()[0]
    ess_count = db.execute("SELECT COUNT(*) FROM essentials_cards").fetchone()[0]
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
      <div class="stat"><div class="num">{speak_count}</div><div class="lbl">Phrases "Parler"</div></div>
      <div class="stat"><div class="num">{ess_count}</div><div class="lbl">Fiches Essentiels</div></div>
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
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
