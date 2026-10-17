# =========================================================
# NATHO — Plateforme d'apprentissage de l'allemand A1
# Version finale : Audio en arrière-plan (Serveur MP3)
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
# CSS & JS (PWA Integration)
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
    © NATHO — Plateforme d'apprentissage de l'allemand A1 · Prototype v3.8<br>
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
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
