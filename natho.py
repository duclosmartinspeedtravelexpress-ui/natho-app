# =========================================================
# NATHO — Plateforme d'apprentissage de l'allemand A1
# Version finale stable : Sidebar + W-Fragen + Audio
# + Apprendre à parler + Essentiels A1 + Mode nuit + Menu mobile
# + NOM/AKK (Nominativ vs Akkusativ) + NEFERTI (bot Sprechen)
# v4.1 : correctifs (sécurité, playlists, progression, Goethe, Neferti, contenu)
# =========================================================

import os
import sqlite3
import hashlib
import secrets
import json
import random
import re
import stat
import hmac
import time
from html import escape as h
from urllib.parse import urlparse
from collections import deque
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (Flask, request, session, redirect, url_for,
                   g, flash, jsonify,
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
DATA_DIR = "/app/data"
DB_PATH = os.path.join(DATA_DIR, "natho.db")

try:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.chmod(DATA_DIR, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
except Exception as e:
    print("Attention dossier data :", e)

def _load_secret():
    """Clé de session STABLE : variable NATHO_SECRET, sinon fichier persistant dans /app/data
    (plus de déconnexion générale à chaque déploiement, identique pour tous les workers)."""
    env = os.environ.get("NATHO_SECRET")
    if env:
        return env
    path = os.path.join(DATA_DIR, ".secret_key")
    for _ in range(5):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                val = fh.read().strip()
            if val:
                return val
        except Exception:
            pass
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            val = secrets.token_hex(32)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(val)
            return val
        except FileExistsError:
            time.sleep(0.2)
        except Exception as e:
            print("Attention clé secrète :", e)
            break
    return secrets.token_hex(32)

APP_SECRET = _load_secret()

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("NATHO_COOKIE_SECURE") or os.environ.get("RAILWAY_ENVIRONMENT")),
    MAX_CONTENT_LENGTH=1024 * 1024,
)

# ---------------------------------------------------------
# BASE DE DONNÉES
# ---------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA busy_timeout=30000")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# Empreinte (SHA-256) de l'ancien mot de passe admin écrit en dur : sert uniquement à le détecter et à le remplacer.
_COMPROMISED_ADMIN_HASH = "0d78ac587831c938635fccd39ed9ad5f21530703a548079554e2a282908c19ae"

def _legacy_hash(pwd: str) -> str:
    return hashlib.sha256(pwd.encode("utf-8")).hexdigest()

def hash_pwd(pwd: str) -> str:
    """Hachage salé (PBKDF2-SHA256)."""
    return generate_password_hash(pwd, method="pbkdf2:sha256", salt_length=16)

def _is_legacy_hash(stored: str) -> bool:
    return not (stored or "").startswith(("pbkdf2:", "scrypt:"))

def check_pwd(stored: str, pwd: str) -> bool:
    """Accepte les nouveaux hachages salés ET les anciens SHA-256 (migrés au prochain login réussi)."""
    if not stored:
        return False
    if not _is_legacy_hash(stored):
        try:
            return check_password_hash(stored, pwd)
        except Exception:
            return False
    return hmac.compare_digest(stored, _legacy_hash(pwd))

def init_db():
    try:
        db = sqlite3.connect(DB_PATH, timeout=30)
        try:
            db.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
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
        admin_env_pwd = os.environ.get("NATHO_ADMIN_PASSWORD", "")

        c.execute("SELECT id, password FROM users WHERE email=?", (admin_email,))
        admin_row = c.fetchone()

        if not admin_row:
            first_pwd = admin_env_pwd or secrets.token_urlsafe(12)
            c.execute("INSERT INTO users(name,email,password,is_admin) VALUES(?,?,?,1)",
                      ("Admin NATHO", admin_email, hash_pwd(first_pwd)))
            if not admin_env_pwd:
                print("=" * 62, flush=True)
                print("ADMIN créé : %s  |  mot de passe initial : %s" % (admin_email, first_pwd), flush=True)
                print("Définis NATHO_ADMIN_PASSWORD sur Railway pour choisir le tien.", flush=True)
                print("=" * 62, flush=True)
        else:
            stored = admin_row[1]
            if admin_env_pwd:
                if not check_pwd(stored, admin_env_pwd):
                    c.execute("UPDATE users SET password=? WHERE id=?", (hash_pwd(admin_env_pwd), admin_row[0]))
            elif stored == _COMPROMISED_ADMIN_HASH:
                new_pwd = secrets.token_urlsafe(12)
                c.execute("UPDATE users SET password=? WHERE id=?", (hash_pwd(new_pwd), admin_row[0]))
                print("=" * 62, flush=True)
                print("L'ancien mot de passe admin (écrit dans le code) a été remplacé.", flush=True)
                print("NOUVEAU mot de passe admin (%s) : %s" % (admin_email, new_pwd), flush=True)
                print("Définis NATHO_ADMIN_PASSWORD sur Railway pour choisir le tien.", flush=True)
                print("=" * 62, flush=True)
            c.execute("UPDATE users SET is_admin=1 WHERE id=?", (admin_row[0],))

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

        c.execute("""CREATE TABLE IF NOT EXISTS nomakk_sections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sec_num INTEGER NOT NULL UNIQUE,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            explanation TEXT NOT NULL DEFAULT ''
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS nomakk_playlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            items_json TEXT NOT NULL
        )""")

        # === NEFERTI : tables (idempotentes, ne touchent pas l'existant) ===
        c.execute("""CREATE TABLE IF NOT EXISTS neferti_scenarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            step_key TEXT NOT NULL UNIQUE,
            neferti_de TEXT NOT NULL,
            neferti_fr TEXT NOT NULL,
            expected_de TEXT NOT NULL DEFAULT '',
            keywords TEXT NOT NULL DEFAULT '',
            followup_yes TEXT DEFAULT '',
            followup_no TEXT DEFAULT '',
            memory_key TEXT DEFAULT '',
            order_index INTEGER DEFAULT 0
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS neferti_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mem_key TEXT NOT NULL,
            mem_value TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, mem_key),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS neferti_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            fr_text TEXT DEFAULT '',
            de_text TEXT DEFAULT '',
            heard_text TEXT DEFAULT '',
            score INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            k TEXT NOT NULL,
            ts REAL NOT NULL
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_k ON login_attempts(k, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_lessons_cat ON lessons(category)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_vocab_cat ON vocab(category)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_neferti_hist_user ON neferti_history(user_id, id)")

        # === SYNCHRONISATION DU CONTENU (idempotente, à chaque démarrage) ===
        # Ajoute ce qui manque et met à jour les fiches / playlists / scénarios modifiés dans le code.
        seed_lessons(c)
        seed_wfragen(c)
        seed_lessons_extra(c)
        seed_dialogues(c)
        seed_vocab(c)
        seed_vocab_extra(c)
        seed_numbers(c)
        seed_speak_phrases(c)
        seed_essentials_cards(c)
        seed_speak_playlists(c)
        seed_nomakk_sections(c)
        seed_nomakk_playlist(c)
        seed_neferti_scenarios(c)

        db.commit()
        db.close()
    except Exception as e:
        print("❌ Erreur d'initialisation :", e)
        import traceback
        traceback.print_exc()

# ---------------------------------------------------------
# CONTENU PÉDAGOGIQUE
# ---------------------------------------------------------
# ---------------------------------------------------------
# SYNCHRONISATION DU CONTENU (idempotente : s'exécute à chaque démarrage et
# n'ajoute que ce qui manque, sans jamais supprimer de leçon ni de progression)
# ---------------------------------------------------------
def _sync_lessons(cursor, data):
    existing = {(r[0], r[1]) for r in cursor.execute("SELECT category, german FROM lessons").fetchall()}
    nxt = cursor.execute("SELECT COALESCE(MAX(order_index), -1) FROM lessons").fetchone()[0] + 1
    for cat, de, fr in data:
        if (cat, de) in existing:
            continue
        cursor.execute(
            "INSERT INTO lessons(category,title,french,german,order_index) VALUES(?,?,?,?,?)",
            (cat, de, fr, de, nxt)
        )
        existing.add((cat, de))
        nxt += 1

def _sync_vocab(cursor, data):
    existing = {(r[0], r[1]) for r in cursor.execute("SELECT category, german FROM vocab").fetchall()}
    for cat, de, fr in data:
        if (cat, de) in existing:
            continue
        cursor.execute("INSERT INTO vocab(category, german, french) VALUES(?,?,?)", (cat, de, fr))
        existing.add((cat, de))

NUMBER_WORDS = [
    ("null", "zéro"), ("eins", "un"), ("zwei", "deux"), ("drei", "trois"), ("vier", "quatre"),
    ("fünf", "cinq"), ("sechs", "six"), ("sieben", "sept"), ("acht", "huit"), ("neun", "neuf"),
    ("zehn", "dix"), ("elf", "onze"), ("zwölf", "douze"), ("dreizehn", "treize"),
    ("vierzehn", "quatorze"), ("fünfzehn", "quinze"), ("sechzehn", "seize"),
    ("siebzehn", "dix-sept"), ("achtzehn", "dix-huit"), ("neunzehn", "dix-neuf"), ("zwanzig", "vingt"),
]


# --- Dialogues (50 × 10 répliques) ---
DIALOGUES_DATA = [
    ("Au supermarché", [
        ("A", "Entschuldigung, wo ist die Milch?", "Excusez-moi, où est le lait ?"),
        ("B", "Die Milch ist dort hinten.", "Le lait est là-bas au fond."),
        ("A", "Danke. Und wo ist das Brot?", "Merci. Et où est le pain ?"),
        ("B", "Das Brot ist neben der Kasse.", "Le pain est à côté de la caisse."),
        ("A", "Hier bitte. Danke!", "Voici, s'il vous plaît. Merci !"),
        ("B", "Danke, schönen Tag noch!", "Merci, bonne journée !"),
        ("A", "Haben Sie auch eine Tüte?", "Avez-vous aussi un sac ?"),
        ("B", "Ja, eine Tüte kostet zehn Cent.", "Oui, un sac coûte dix centimes."),
        ("A", "Gut, eine Tüte bitte.", "Bien, un sac s'il vous plaît."),
        ("B", "Hier ist Ihre Tüte.", "Voici votre sac."),
    ]),
    ("À la gare", [
        ("A", "Guten Tag, wann fährt der nächste Zug nach Berlin?", "Bonjour, quand part le prochain train pour Berlin ?"),
        ("B", "Um 14:30 Uhr, Gleis 3.", "À 14h30, voie 3."),
        ("A", "Wie lange dauert die Fahrt?", "Combien de temps dure le trajet ?"),
        ("B", "Etwa zwei Stunden.", "Environ deux heures."),
        ("A", "Hier bitte. Danke!", "Voici. Merci !"),
        ("B", "Gute Reise!", "Bon voyage !"),
        ("A", "Noch eine Frage: Wo ist Gleis 3?", "Encore une question : où est la voie 3 ?"),
        ("B", "Dort links, die Treppe hinunter.", "Là à gauche, en descendant l'escalier."),
        ("A", "Vielen Dank für Ihre Hilfe!", "Merci beaucoup pour votre aide !"),
        ("B", "Gern geschehen!", "Avec plaisir !"),
    ]),
    ("Au café", [
        ("A", "Guten Morgen! Einen Kaffee, bitte.", "Bonjour ! Un café, s'il vous plaît."),
        ("B", "Gern. Mit Milch und Zucker?", "Volontiers. Avec du lait et du sucre ?"),
        ("A", "Mit Milch, ohne Zucker.", "Avec du lait, sans sucre."),
        ("B", "Möchten Sie auch ein Stück Kuchen?", "Voulez-vous aussi une part de gâteau ?"),
        ("A", "Ja, ein Stück Schokoladenkuchen.", "Oui, une part de gâteau au chocolat."),
        ("B", "Das macht vier Euro fünfzig.", "Cela fait quatre euros cinquante."),
        ("A", "Kann ich mit Karte zahlen?", "Puis-je payer par carte ?"),
        ("B", "Natürlich, hier ist das Gerät.", "Bien sûr, voici le terminal."),
        ("A", "Wo kann ich mich setzen?", "Où puis-je m'asseoir ?"),
        ("B", "Am Fenster ist ein Tisch frei.", "Il y a une table libre près de la fenêtre."),
    ]),
    ("Au restaurant", [
        ("A", "Guten Abend. Ein Tisch für zwei, bitte.", "Bonsoir. Une table pour deux, s'il vous plaît."),
        ("B", "Gern. Hier ist die Speisekarte.", "Volontiers. Voici la carte."),
        ("A", "Was empfehlen Sie heute?", "Que recommandez-vous aujourd'hui ?"),
        ("B", "Die Hühnersuppe ist sehr gut.", "La soupe de poulet est très bonne."),
        ("A", "Dann nehme ich die Suppe und ein Wasser.", "Alors je prends la soupe et une eau."),
        ("B", "Und für Ihre Frau?", "Et pour votre épouse ?"),
        ("A", "Sie möchte Fisch mit Reis.", "Elle voudrait du poisson avec du riz."),
        ("B", "Sehr gut. Ich bringe gleich die Getränke.", "Très bien. J'apporte les boissons tout de suite."),
        ("A", "Die Rechnung bitte!", "L'addition, s'il vous plaît !"),
        ("B", "Das sind zweiunddreißig Euro.", "Cela fait trente-deux euros."),
    ]),
    ("À la boulangerie", [
        ("A", "Guten Morgen! Was darf es sein?", "Bonjour ! Que désirez-vous ?"),
        ("B", "Ich möchte drei Brötchen, bitte.", "Je voudrais trois petits pains, s'il vous plaît."),
        ("A", "Sonst noch etwas?", "Autre chose ?"),
        ("B", "Ja, ein Vollkornbrot, bitte.", "Oui, un pain complet, s'il vous plaît."),
        ("A", "Möchten Sie das Brot geschnitten?", "Voulez-vous le pain tranché ?"),
        ("B", "Ja, bitte geschnitten.", "Oui, tranché s'il vous plaît."),
        ("A", "Das macht drei Euro zwanzig.", "Cela fait trois euros vingt."),
        ("B", "Hier sind fünf Euro.", "Voici cinq euros."),
        ("A", "Und achtzig Cent zurück. Bitte sehr!", "Et quatre-vingts centimes de monnaie. Je vous en prie !"),
        ("B", "Vielen Dank, bis morgen!", "Merci beaucoup, à demain !"),
    ]),
    ("Au marché", [
        ("A", "Hallo! Wie viel kosten die Tomaten?", "Bonjour ! Combien coûtent les tomates ?"),
        ("B", "Zwei Euro das Kilo.", "Deux euros le kilo."),
        ("A", "Das ist günstig. Ich nehme zwei Kilo.", "C'est bon marché. J'en prends deux kilos."),
        ("B", "Brauchen Sie auch Zwiebeln?", "Avez-vous aussi besoin d'oignons ?"),
        ("A", "Ja, ein Kilo Zwiebeln, bitte.", "Oui, un kilo d'oignons, s'il vous plaît."),
        ("B", "Hier, alles frisch von heute Morgen.", "Voilà, tout est frais de ce matin."),
        ("A", "Haben Sie auch Bananen?", "Avez-vous aussi des bananes ?"),
        ("B", "Leider nicht, aber Äpfel.", "Malheureusement non, mais des pommes."),
        ("A", "Dann bitte noch fünf Äpfel.", "Alors encore cinq pommes, s'il vous plaît."),
        ("B", "Zusammen sieben Euro, bitte.", "Ensemble sept euros, s'il vous plaît."),
    ]),
    ("À la pharmacie", [
        ("A", "Guten Tag, ich habe Kopfschmerzen.", "Bonjour, j'ai mal à la tête."),
        ("B", "Seit wann haben Sie die Schmerzen?", "Depuis quand avez-vous mal ?"),
        ("A", "Seit gestern Abend.", "Depuis hier soir."),
        ("B", "Hier sind Tabletten gegen Kopfschmerzen.", "Voici des comprimés contre le mal de tête."),
        ("A", "Wie oft muss ich sie nehmen?", "Combien de fois dois-je les prendre ?"),
        ("B", "Dreimal am Tag, nach dem Essen.", "Trois fois par jour, après le repas."),
        ("A", "Brauche ich ein Rezept?", "Ai-je besoin d'une ordonnance ?"),
        ("B", "Nein, die Tabletten sind frei verkäuflich.", "Non, les comprimés se vendent sans ordonnance."),
        ("A", "Und was kostet das zusammen?", "Et combien cela coûte-t-il ensemble ?"),
        ("B", "Fünf Euro neunzig. Gute Besserung!", "Cinq euros quatre-vingt-dix. Bon rétablissement !"),
    ]),
    ("Chez le médecin", [
        ("A", "Guten Tag, Frau Weber. Wie geht es Ihnen?", "Bonjour, Madame Weber. Comment allez-vous ?"),
        ("B", "Nicht gut. Ich habe Fieber und Husten.", "Pas bien. J'ai de la fièvre et je tousse."),
        ("A", "Haben Sie auch Halsschmerzen?", "Avez-vous aussi mal à la gorge ?"),
        ("B", "Ja, der Hals tut sehr weh.", "Oui, la gorge me fait très mal."),
        ("A", "Bitte öffnen Sie den Mund.", "Ouvrez la bouche, s'il vous plaît."),
        ("B", "Ist es schlimm, Herr Doktor?", "Est-ce grave, docteur ?"),
        ("A", "Nein, Sie haben eine Erkältung.", "Non, vous avez un rhume."),
        ("B", "Muss ich im Bett bleiben?", "Dois-je rester au lit ?"),
        ("A", "Ja, drei Tage. Und trinken Sie viel Tee.", "Oui, trois jours. Et buvez beaucoup de thé."),
        ("B", "Vielen Dank, Herr Doktor.", "Merci beaucoup, docteur."),
    ]),
    ("Réserver une chambre d'hôtel", [
        ("A", "Hotel Sonne, guten Tag. Was kann ich tun?", "Hôtel Sonne, bonjour. Que puis-je faire pour vous ?"),
        ("B", "Ich möchte ein Zimmer reservieren.", "Je voudrais réserver une chambre."),
        ("A", "Für wie viele Personen?", "Pour combien de personnes ?"),
        ("B", "Für zwei Personen, drei Nächte.", "Pour deux personnes, trois nuits."),
        ("A", "Ab wann möchten Sie das Zimmer?", "À partir de quand voulez-vous la chambre ?"),
        ("B", "Ab dem zwölften Mai.", "À partir du douze mai."),
        ("A", "Ein Doppelzimmer kostet siebzig Euro pro Nacht.", "Une chambre double coûte soixante-dix euros par nuit."),
        ("B", "Ist das Frühstück dabei?", "Le petit-déjeuner est-il compris ?"),
        ("A", "Ja, von sieben bis zehn Uhr.", "Oui, de sept heures à dix heures."),
        ("B", "Super, ich nehme das Zimmer. Mein Name ist Keller.", "Super, je prends la chambre. Mon nom est Keller."),
    ]),
    ("Arrivée à l'hôtel", [
        ("A", "Guten Abend. Ich habe ein Zimmer reserviert.", "Bonsoir. J'ai réservé une chambre."),
        ("B", "Wie ist Ihr Name, bitte?", "Quel est votre nom, s'il vous plaît ?"),
        ("A", "Ich heiße Samuel Ndongo.", "Je m'appelle Samuel Ndongo."),
        ("B", "Ja, hier. Zimmer zwölf im ersten Stock.", "Oui, voilà. Chambre douze au premier étage."),
        ("A", "Gibt es hier einen Aufzug?", "Y a-t-il un ascenseur ici ?"),
        ("B", "Ja, dort neben der Tür.", "Oui, là à côté de la porte."),
        ("A", "Ist das WLAN gratis?", "Le wifi est-il gratuit ?"),
        ("B", "Ja, das Passwort steht auf der Karte.", "Oui, le mot de passe est sur la carte."),
        ("A", "Wann gibt es Frühstück?", "Quand y a-t-il le petit-déjeuner ?"),
        ("B", "Ab sieben Uhr im Restaurant. Gute Nacht!", "À partir de sept heures au restaurant. Bonne nuit !"),
    ]),
    ("Départ de l'hôtel", [
        ("A", "Guten Morgen. Ich möchte auschecken.", "Bonjour. Je voudrais partir de l'hôtel."),
        ("B", "Natürlich. Welche Zimmernummer haben Sie?", "Bien sûr. Quel est votre numéro de chambre ?"),
        ("A", "Zimmer zwölf.", "La chambre douze."),
        ("B", "Hatten Sie etwas aus der Minibar?", "Avez-vous pris quelque chose dans le minibar ?"),
        ("A", "Nein, nur eine Flasche Wasser.", "Non, seulement une bouteille d'eau."),
        ("B", "Dann zahlen Sie zweihundertzehn Euro.", "Alors vous payez deux cent dix euros."),
        ("A", "Kann ich bar bezahlen?", "Puis-je payer en espèces ?"),
        ("B", "Ja, natürlich. Brauchen Sie eine Quittung?", "Oui, bien sûr. Avez-vous besoin d'un reçu ?"),
        ("A", "Ja, bitte. Das Hotel war sehr schön.", "Oui, s'il vous plaît. L'hôtel était très beau."),
        ("B", "Danke! Kommen Sie bald wieder.", "Merci ! Revenez bientôt."),
    ]),
    ("À l'aéroport", [
        ("A", "Guten Tag. Ihren Pass, bitte.", "Bonjour. Votre passeport, s'il vous plaît."),
        ("B", "Hier ist mein Pass.", "Voici mon passeport."),
        ("A", "Haben Sie Gepäck?", "Avez-vous des bagages ?"),
        ("B", "Ja, einen Koffer und eine Tasche.", "Oui, une valise et un sac."),
        ("A", "Bitte stellen Sie den Koffer hier hin.", "Posez la valise ici, s'il vous plaît."),
        ("B", "Er ist nicht schwer, glaube ich.", "Elle n'est pas lourde, je crois."),
        ("A", "Das stimmt. Hier ist Ihre Bordkarte.", "C'est exact. Voici votre carte d'embarquement."),
        ("B", "Von welchem Gate fliege ich?", "De quelle porte est-ce que je pars ?"),
        ("A", "Gate B zwölf. Das Boarding beginnt um 9 Uhr.", "Porte B douze. L'embarquement commence à 9 heures."),
        ("B", "Vielen Dank und einen schönen Tag!", "Merci beaucoup et bonne journée !"),
    ]),
    ("Dans le bus", [
        ("A", "Entschuldigung, fährt dieser Bus zum Zentrum?", "Excusez-moi, ce bus va-t-il au centre ?"),
        ("B", "Ja, die Linie fünf fährt ins Zentrum.", "Oui, la ligne cinq va au centre."),
        ("A", "Was kostet eine Fahrkarte?", "Combien coûte un ticket ?"),
        ("B", "Zwei Euro, beim Fahrer.", "Deux euros, chez le conducteur."),
        ("A", "Danke. Wie viele Haltestellen sind es?", "Merci. Combien d'arrêts y a-t-il ?"),
        ("B", "Es sind sechs Haltestellen.", "Il y a six arrêts."),
        ("A", "Ist hier noch ein Platz frei?", "Cette place est-elle encore libre ?"),
        ("B", "Ja, bitte setzen Sie sich.", "Oui, asseyez-vous, je vous prie."),
        ("A", "Wo muss ich aussteigen?", "Où dois-je descendre ?"),
        ("B", "Am Rathaus. Ich sage Ihnen Bescheid.", "À la mairie. Je vous préviendrai."),
    ]),
    ("Dans le métro", [
        ("A", "Hallo Lena, welche U-Bahn nehmen wir?", "Salut Lena, quel métro prenons-nous ?"),
        ("B", "Wir nehmen die U2 Richtung Hauptbahnhof.", "Nous prenons la U2 direction gare centrale."),
        ("A", "Müssen wir umsteigen?", "Devons-nous changer ?"),
        ("B", "Ja, am Marktplatz steigen wir um.", "Oui, nous changeons à Marktplatz."),
        ("A", "Hast du die Tickets schon?", "As-tu déjà les tickets ?"),
        ("B", "Ja, ich habe zwei Tickets gekauft.", "Oui, j'ai acheté deux tickets."),
        ("A", "Wie spät ist es jetzt?", "Quelle heure est-il maintenant ?"),
        ("B", "Es ist Viertel vor zehn.", "Il est dix heures moins le quart."),
        ("A", "Dann kommen wir pünktlich an.", "Alors nous arrivons à l'heure."),
        ("B", "Ja, die nächste Station ist unsere.", "Oui, la prochaine station est la nôtre."),
    ]),
    ("En taxi", [
        ("A", "Taxi! Sind Sie frei?", "Taxi ! Êtes-vous libre ?"),
        ("B", "Ja, steigen Sie ein. Wohin fahren wir?", "Oui, montez. Où allons-nous ?"),
        ("A", "Zum Hotel Sonne in der Bahnhofstraße.", "À l'hôtel Sonne dans la Bahnhofstraße."),
        ("B", "Kein Problem. Das dauert zehn Minuten.", "Pas de problème. Ça dure dix minutes."),
        ("A", "Können Sie bitte den Koffer nehmen?", "Pouvez-vous prendre la valise, s'il vous plaît ?"),
        ("B", "Natürlich, er kommt in den Kofferraum.", "Bien sûr, elle va dans le coffre."),
        ("A", "Wie viel kostet die Fahrt ungefähr?", "Combien coûte le trajet environ ?"),
        ("B", "Ungefähr fünfzehn Euro.", "Environ quinze euros."),
        ("A", "Hier sind zwanzig Euro. Der Rest ist für Sie.", "Voici vingt euros. Gardez la monnaie."),
        ("B", "Das ist nett, vielen Dank!", "C'est gentil, merci beaucoup !"),
    ]),
    ("Demander son chemin", [
        ("A", "Entschuldigen Sie, wo ist die Post?", "Excusez-moi, où est la poste ?"),
        ("B", "Gehen Sie hier geradeaus.", "Allez tout droit ici."),
        ("A", "Und dann?", "Et ensuite ?"),
        ("B", "Dann nehmen Sie die zweite Straße rechts.", "Ensuite prenez la deuxième rue à droite."),
        ("A", "Ist es weit von hier?", "Est-ce loin d'ici ?"),
        ("B", "Nein, nur fünf Minuten zu Fuß.", "Non, seulement cinq minutes à pied."),
        ("A", "Wie sieht das Gebäude aus?", "À quoi ressemble le bâtiment ?"),
        ("B", "Es ist gelb und steht neben der Kirche.", "Il est jaune et se trouve à côté de l'église."),
        ("A", "Ich glaube, ich habe alles verstanden.", "Je crois que j'ai tout compris."),
        ("B", "Sehr gut. Viel Glück!", "Très bien. Bonne chance !"),
    ]),
    ("Se présenter", [
        ("A", "Hallo! Ich heiße Fatou. Und du?", "Salut ! Je m'appelle Fatou. Et toi ?"),
        ("B", "Hallo Fatou, ich bin Paul. Freut mich!", "Salut Fatou, je suis Paul. Enchanté !"),
        ("A", "Woher kommst du, Paul?", "D'où viens-tu, Paul ?"),
        ("B", "Ich komme aus Hamburg. Und du?", "Je viens de Hambourg. Et toi ?"),
        ("A", "Ich komme aus Kamerun, aus Yaoundé.", "Je viens du Cameroun, de Yaoundé."),
        ("B", "Ah, interessant! Was machst du hier?", "Ah, intéressant ! Que fais-tu ici ?"),
        ("A", "Ich lerne Deutsch und studiere Informatik.", "J'apprends l'allemand et j'étudie l'informatique."),
        ("B", "Wie alt bist du?", "Quel âge as-tu ?"),
        ("A", "Ich bin zwanzig Jahre alt.", "J'ai vingt ans."),
        ("B", "Ich bin auch zwanzig. Wir sind gleich alt!", "J'ai aussi vingt ans. Nous avons le même âge !"),
    ]),
    ("Rencontrer un voisin", [
        ("A", "Guten Tag! Ich bin Ihr neuer Nachbar.", "Bonjour ! Je suis votre nouveau voisin."),
        ("B", "Herzlich willkommen! Ich heiße Müller.", "Bienvenue ! Je m'appelle Müller."),
        ("A", "Mein Name ist Ibrahim. Ich wohne im dritten Stock.", "Mon nom est Ibrahim. J'habite au troisième étage."),
        ("B", "Ich wohne direkt unter Ihnen.", "J'habite juste en dessous de vous."),
        ("A", "Dann bin ich abends bitte leise.", "Alors je serai silencieux le soir."),
        ("B", "Das ist sehr nett von Ihnen.", "C'est très gentil de votre part."),
        ("A", "Wo kann ich hier gut einkaufen?", "Où puis-je bien faire mes courses ici ?"),
        ("B", "Der Supermarkt ist um die Ecke.", "Le supermarché est au coin de la rue."),
        ("A", "Danke für den Tipp, Herr Müller.", "Merci pour le conseil, Monsieur Müller."),
        ("B", "Bitte, bei Fragen klingeln Sie einfach.", "Je vous en prie, si vous avez des questions, sonnez simplement."),
    ]),
    ("Au téléphone : un rendez-vous", [
        ("A", "Praxis Doktor Braun, guten Tag.", "Cabinet du docteur Braun, bonjour."),
        ("B", "Guten Tag, ich brauche einen Termin.", "Bonjour, j'ai besoin d'un rendez-vous."),
        ("A", "Wann haben Sie Zeit?", "Quand avez-vous du temps ?"),
        ("B", "Am Dienstag oder am Mittwoch.", "Mardi ou mercredi."),
        ("A", "Dienstag um zehn Uhr ist frei.", "Mardi à dix heures, c'est libre."),
        ("B", "Das passt gut. Danke.", "Ça me convient bien. Merci."),
        ("A", "Und auf welchen Namen, bitte?", "Et à quel nom, s'il vous plaît ?"),
        ("B", "Anna Schmidt. Soll ich etwas mitbringen?", "Anna Schmidt. Dois-je apporter quelque chose ?"),
        ("A", "Bringen Sie bitte Ihre Versicherungskarte mit.", "Apportez votre carte d'assurance, s'il vous plaît."),
        ("B", "Mache ich. Bis Dienstag!", "Je le ferai. À mardi !"),
    ]),
    ("Au téléphone : en retard", [
        ("A", "Hallo Tom, wo bist du denn?", "Allô Tom, où es-tu donc ?"),
        ("B", "Es tut mir leid, ich bin im Stau.", "Je suis désolé, je suis dans les embouteillages."),
        ("A", "Wir warten schon zwanzig Minuten.", "Nous attendons déjà depuis vingt minutes."),
        ("B", "Ich weiß. Ich komme in zehn Minuten.", "Je sais. J'arrive dans dix minutes."),
        ("A", "Soll ich schon bestellen?", "Dois-je déjà commander ?"),
        ("B", "Ja, bestell mir bitte eine Cola.", "Oui, commande-moi un coca s'il te plaît."),
        ("A", "Und etwas zu essen?", "Et quelque chose à manger ?"),
        ("B", "Eine Pizza, wie immer.", "Une pizza, comme toujours."),
        ("A", "Okay, kein Problem. Fahr vorsichtig!", "D'accord, pas de problème. Conduis prudemment !"),
        ("B", "Danke für dein Verständnis. Bis gleich!", "Merci de ta compréhension. À tout de suite !"),
    ]),
    ("À la banque", [
        ("A", "Guten Tag, ich möchte ein Konto eröffnen.", "Bonjour, je voudrais ouvrir un compte."),
        ("B", "Gern. Haben Sie Ihren Ausweis dabei?", "Volontiers. Avez-vous votre pièce d'identité ?"),
        ("A", "Ja, hier ist mein Pass.", "Oui, voici mon passeport."),
        ("B", "Wo wohnen Sie?", "Où habitez-vous ?"),
        ("A", "Ich wohne in der Gartenstraße vierzehn.", "J'habite au quatorze Gartenstraße."),
        ("B", "Möchten Sie auch eine Bankkarte?", "Voulez-vous aussi une carte bancaire ?"),
        ("A", "Ja, bitte. Was kostet sie?", "Oui, s'il vous plaît. Combien coûte-t-elle ?"),
        ("B", "Die Karte ist im ersten Jahr kostenlos.", "La carte est gratuite la première année."),
        ("A", "Das ist gut. Wann bekomme ich sie?", "C'est bien. Quand la recevrai-je ?"),
        ("B", "In einer Woche, per Post.", "Dans une semaine, par la poste."),
    ]),
    ("À la poste", [
        ("A", "Guten Tag, ich möchte dieses Paket nach Kamerun schicken.", "Bonjour, je voudrais envoyer ce colis au Cameroun."),
        ("B", "Legen Sie es bitte auf die Waage.", "Posez-le sur la balance, s'il vous plaît."),
        ("A", "Wie schwer ist es?", "Combien pèse-t-il ?"),
        ("B", "Drei Kilo. Das kostet vierzig Euro.", "Trois kilos. Cela coûte quarante euros."),
        ("A", "Wie lange dauert das?", "Combien de temps cela prend-il ?"),
        ("B", "Ungefähr zehn Tage.", "Environ dix jours."),
        ("A", "Ich brauche auch Briefmarken.", "J'ai aussi besoin de timbres."),
        ("B", "Wie viele Briefmarken möchten Sie?", "Combien de timbres voulez-vous ?"),
        ("A", "Fünf Stück, bitte, für Postkarten.", "Cinq, s'il vous plaît, pour des cartes postales."),
        ("B", "Alles zusammen macht fünfzig Euro.", "Le tout fait cinquante euros."),
    ]),
    ("Au magasin de vêtements", [
        ("A", "Guten Tag, ich suche eine Jacke.", "Bonjour, je cherche une veste."),
        ("B", "Welche Größe haben Sie?", "Quelle taille faites-vous ?"),
        ("A", "Ich trage Größe M.", "Je porte du M."),
        ("B", "Wie gefällt Ihnen diese blaue Jacke?", "Que pensez-vous de cette veste bleue ?"),
        ("A", "Sie ist schön. Kann ich sie anprobieren?", "Elle est belle. Puis-je l'essayer ?"),
        ("B", "Natürlich, die Kabine ist dort.", "Bien sûr, la cabine est là-bas."),
        ("A", "Sie passt gut, aber sie ist ein bisschen teuer.", "Elle me va bien, mais elle est un peu chère."),
        ("B", "Heute gibt es zwanzig Prozent Rabatt.", "Aujourd'hui il y a vingt pour cent de réduction."),
        ("A", "Wunderbar, dann kaufe ich sie.", "Merveilleux, alors je l'achète."),
        ("B", "Die Kasse ist gleich hier vorne.", "La caisse est juste ici devant."),
    ]),
    ("Au magasin de téléphones", [
        ("A", "Hallo, mein Handy ist kaputt.", "Bonjour, mon téléphone est cassé."),
        ("B", "Was ist das Problem?", "Quel est le problème ?"),
        ("A", "Der Bildschirm ist gebrochen.", "L'écran est cassé."),
        ("B", "Das kann man reparieren. Es dauert zwei Tage.", "On peut le réparer. Cela prend deux jours."),
        ("A", "Was kostet die Reparatur?", "Combien coûte la réparation ?"),
        ("B", "Neunzig Euro.", "Quatre-vingt-dix euros."),
        ("A", "Das ist zu teuer für mich.", "C'est trop cher pour moi."),
        ("B", "Wir haben auch günstige neue Handys.", "Nous avons aussi des téléphones neufs pas chers."),
        ("A", "Zeigen Sie mir bitte eines.", "Montrez-m'en un, s'il vous plaît."),
        ("B", "Dieses hier kostet nur neunundsechzig Euro.", "Celui-ci coûte seulement soixante-neuf euros."),
    ]),
    ("À la bibliothèque", [
        ("A", "Guten Tag, ich möchte ein Buch ausleihen.", "Bonjour, je voudrais emprunter un livre."),
        ("B", "Haben Sie einen Bibliotheksausweis?", "Avez-vous une carte de bibliothèque ?"),
        ("A", "Nein, ich bin neu hier.", "Non, je suis nouveau ici."),
        ("B", "Dann brauche ich Ihren Namen und Ihre Adresse.", "Alors j'ai besoin de votre nom et de votre adresse."),
        ("A", "Ich heiße Lena Fischer und wohne in der Lindenallee.", "Je m'appelle Lena Fischer et j'habite Lindenallee."),
        ("B", "Hier ist Ihr Ausweis. Welches Buch suchen Sie?", "Voici votre carte. Quel livre cherchez-vous ?"),
        ("A", "Ich suche ein einfaches Buch für Anfänger.", "Je cherche un livre simple pour débutants."),
        ("B", "Die Bücher stehen dort im Regal.", "Les livres sont là-bas sur l'étagère."),
        ("A", "Wie lange darf ich es behalten?", "Combien de temps puis-je le garder ?"),
        ("B", "Vier Wochen. Danach bringen Sie es zurück.", "Quatre semaines. Ensuite vous le rapportez."),
    ]),
    ("Au cours d'allemand", [
        ("A", "Guten Morgen, liebe Schüler!", "Bonjour, chers élèves !"),
        ("B", "Guten Morgen, Frau Lehrerin!", "Bonjour, Madame !"),
        ("A", "Öffnet bitte das Buch auf Seite zehn.", "Ouvrez le livre à la page dix, s'il vous plaît."),
        ("B", "Entschuldigung, ich habe mein Buch vergessen.", "Excusez-moi, j'ai oublié mon livre."),
        ("A", "Das ist kein Problem. Schau mit Paul zusammen.", "Ce n'est pas grave. Regarde avec Paul."),
        ("B", "Wie sagt man Bonjour auf Deutsch?", "Comment dit-on bonjour en allemand ?"),
        ("A", "Man sagt Guten Tag oder Hallo.", "On dit Guten Tag ou Hallo."),
        ("B", "Können Sie das bitte wiederholen?", "Pouvez-vous répéter, s'il vous plaît ?"),
        ("A", "Gern. Noch einmal langsam: Guten Tag.", "Volontiers. Encore une fois lentement : Guten Tag."),
        ("B", "Jetzt habe ich es verstanden. Danke!", "Maintenant j'ai compris. Merci !"),
    ]),
    ("À l'université", [
        ("A", "Hallo, ich suche Raum zweihundertfünf.", "Salut, je cherche la salle deux cent cinq."),
        ("B", "Der Raum ist im zweiten Stock.", "La salle est au deuxième étage."),
        ("A", "Bist du auch neu an der Uni?", "Es-tu aussi nouveau à la fac ?"),
        ("B", "Ja, ich studiere Biologie im ersten Semester.", "Oui, j'étudie la biologie en premier semestre."),
        ("A", "Ich auch! Ich heiße Samuel.", "Moi aussi ! Je m'appelle Samuel."),
        ("B", "Freut mich, Samuel. Ich bin Mia.", "Enchantée, Samuel. Je suis Mia."),
        ("A", "Wann beginnt die Vorlesung?", "Quand commence le cours magistral ?"),
        ("B", "Um Viertel nach acht. Wir sind spät!", "À huit heures et quart. Nous sommes en retard !"),
        ("A", "Dann laufen wir schnell.", "Alors courons vite."),
        ("B", "Nach der Vorlesung trinken wir einen Kaffee.", "Après le cours, nous boirons un café."),
    ]),
    ("Un entretien d'embauche", [
        ("A", "Guten Tag, Herr Okafor. Bitte nehmen Sie Platz.", "Bonjour, Monsieur Okafor. Asseyez-vous, je vous prie."),
        ("B", "Guten Tag. Vielen Dank für die Einladung.", "Bonjour. Merci beaucoup pour l'invitation."),
        ("A", "Erzählen Sie bitte kurz von sich.", "Parlez un peu de vous, s'il vous plaît."),
        ("B", "Ich bin dreißig Jahre alt und komme aus Douala.", "J'ai trente ans et je viens de Douala."),
        ("A", "Was ist Ihr Beruf?", "Quel est votre métier ?"),
        ("B", "Ich bin Verkäufer und arbeite seit fünf Jahren.", "Je suis vendeur et je travaille depuis cinq ans."),
        ("A", "Welche Sprachen sprechen Sie?", "Quelles langues parlez-vous ?"),
        ("B", "Ich spreche Französisch, Englisch und ein bisschen Deutsch.", "Je parle français, anglais et un peu allemand."),
        ("A", "Wann können Sie anfangen?", "Quand pouvez-vous commencer ?"),
        ("B", "Ich kann sofort anfangen.", "Je peux commencer tout de suite."),
    ]),
    ("Au bureau", [
        ("A", "Guten Morgen, Frau Klein! Wie war das Wochenende?", "Bonjour, Madame Klein ! Comment était le week-end ?"),
        ("B", "Sehr schön, danke. Und Ihr Wochenende?", "Très beau, merci. Et votre week-end ?"),
        ("A", "Auch gut. Haben wir heute eine Besprechung?", "Bien aussi. Avons-nous une réunion aujourd'hui ?"),
        ("B", "Ja, um elf Uhr im Konferenzraum.", "Oui, à onze heures dans la salle de réunion."),
        ("A", "Muss ich etwas vorbereiten?", "Dois-je préparer quelque chose ?"),
        ("B", "Bitte drucken Sie die Liste aus.", "Imprimez la liste, s'il vous plaît."),
        ("A", "Der Drucker funktioniert leider nicht.", "L'imprimante ne fonctionne malheureusement pas."),
        ("B", "Dann benutzen Sie den Drucker im Flur.", "Alors utilisez l'imprimante dans le couloir."),
        ("A", "Gut, das mache ich sofort.", "Bien, je le fais tout de suite."),
        ("B", "Danke, ich hole uns einen Kaffee.", "Merci, je vais nous chercher un café."),
    ]),
    ("Visiter un appartement", [
        ("A", "Guten Tag, ich bin wegen der Wohnung hier.", "Bonjour, je suis là pour l'appartement."),
        ("B", "Willkommen! Kommen Sie bitte herein.", "Bienvenue ! Entrez, je vous prie."),
        ("A", "Wie viele Zimmer hat die Wohnung?", "Combien de pièces a l'appartement ?"),
        ("B", "Zwei Zimmer, eine Küche und ein Bad.", "Deux pièces, une cuisine et une salle de bains."),
        ("A", "Das Wohnzimmer ist schön hell.", "Le salon est joliment lumineux."),
        ("B", "Ja, und der Balkon ist auch groß.", "Oui, et le balcon est grand aussi."),
        ("A", "Wie hoch ist die Miete?", "À combien s'élève le loyer ?"),
        ("B", "Sechshundert Euro im Monat.", "Six cents euros par mois."),
        ("A", "Sind die Nebenkosten dabei?", "Les charges sont-elles comprises ?"),
        ("B", "Nein, die kommen noch dazu.", "Non, elles s'ajoutent."),
    ]),
    ("Une fête", [
        ("A", "Hallo Fatou, schön, dass du da bist!", "Salut Fatou, content que tu sois là !"),
        ("B", "Danke für die Einladung, Max. Tolle Party!", "Merci pour l'invitation, Max. Super fête !"),
        ("A", "Möchtest du etwas trinken?", "Veux-tu boire quelque chose ?"),
        ("B", "Ja, ein Glas Orangensaft, bitte.", "Oui, un verre de jus d'orange, s'il te plaît."),
        ("A", "Das Essen steht auf dem Tisch.", "Le repas est sur la table."),
        ("B", "Mmh, der Salat sieht lecker aus.", "Mmh, la salade a l'air délicieuse."),
        ("A", "Den hat meine Schwester gemacht.", "C'est ma sœur qui l'a faite."),
        ("B", "Spielt ihr auch Musik zum Tanzen?", "Mettez-vous aussi de la musique pour danser ?"),
        ("A", "Ja, gleich geht es los.", "Oui, ça commence tout de suite."),
        ("B", "Super, ich tanze sehr gern!", "Super, j'aime beaucoup danser !"),
    ]),
    ("Un anniversaire", [
        ("A", "Alles Gute zum Geburtstag, Anna!", "Joyeux anniversaire, Anna !"),
        ("B", "Danke, Paul! Wie nett von dir.", "Merci, Paul ! C'est gentil de ta part."),
        ("A", "Das Geschenk ist für dich.", "Le cadeau est pour toi."),
        ("B", "Oh, ein Buch! Das habe ich mir gewünscht.", "Oh, un livre ! Je le désirais."),
        ("A", "Wie alt wirst du heute?", "Quel âge as-tu aujourd'hui ?"),
        ("B", "Ich werde fünfundzwanzig.", "J'ai vingt-cinq ans."),
        ("A", "Wann feierst du mit deiner Familie?", "Quand fêtes-tu avec ta famille ?"),
        ("B", "Heute Abend, wir essen zusammen.", "Ce soir, nous mangeons ensemble."),
        ("A", "Gibt es auch einen Kuchen?", "Y a-t-il aussi un gâteau ?"),
        ("B", "Ja, und du bekommst das erste Stück.", "Oui, et tu auras la première part."),
    ]),
    ("Une invitation à dîner", [
        ("A", "Hast du am Samstag Zeit, Ibrahim?", "As-tu du temps samedi, Ibrahim ?"),
        ("B", "Ja, warum fragst du?", "Oui, pourquoi demandes-tu ?"),
        ("A", "Ich lade dich zum Abendessen ein.", "Je t'invite à dîner."),
        ("B", "Das ist eine tolle Idee! Um wie viel Uhr?", "C'est une super idée ! À quelle heure ?"),
        ("A", "Um sieben Uhr bei mir zu Hause.", "À sept heures chez moi."),
        ("B", "Was kann ich mitbringen?", "Que puis-je apporter ?"),
        ("A", "Bring einfach ein Getränk mit.", "Apporte simplement une boisson."),
        ("B", "Gern. Was kochst du denn?", "Volontiers. Que cuisines-tu donc ?"),
        ("A", "Ich koche Reis mit Hähnchen.", "Je cuisine du riz avec du poulet."),
        ("B", "Wunderbar, ich freue mich schon!", "Merveilleux, je me réjouis déjà !"),
    ]),
    ("Au cinéma", [
        ("A", "Zwei Karten für den Film um acht Uhr, bitte.", "Deux billets pour le film de huit heures, s'il vous plaît."),
        ("B", "Welchen Film möchten Sie sehen?", "Quel film voulez-vous voir ?"),
        ("A", "Die Komödie im Saal drei.", "La comédie dans la salle trois."),
        ("B", "Die Plätze in Reihe sieben sind noch frei.", "Les places au rang sept sont encore libres."),
        ("A", "Perfekt. Was kostet das?", "Parfait. Combien ça coûte ?"),
        ("B", "Zwölf Euro pro Karte.", "Douze euros par billet."),
        ("A", "Hier sind vierundzwanzig Euro.", "Voici vingt-quatre euros."),
        ("B", "Danke. Der Saal ist dort links.", "Merci. La salle est là à gauche."),
        ("A", "Gibt es hier auch Popcorn?", "Y a-t-il aussi du pop-corn ici ?"),
        ("B", "Ja, an der Theke neben dem Eingang.", "Oui, au comptoir à côté de l'entrée."),
    ]),
    ("Au stade", [
        ("A", "Wir sind endlich im Stadion, Samuel!", "Nous sommes enfin au stade, Samuel !"),
        ("B", "Ja, und unsere Plätze sind gut.", "Oui, et nos places sont bonnes."),
        ("A", "Wie spielt unsere Mannschaft heute?", "Comment joue notre équipe aujourd'hui ?"),
        ("B", "Sie spielt gegen Bremen.", "Elle joue contre Brême."),
        ("A", "Welche Farbe hat das Trikot?", "De quelle couleur est le maillot ?"),
        ("B", "Unser Trikot ist rot und weiß.", "Notre maillot est rouge et blanc."),
        ("A", "Tor! Wir haben ein Tor geschossen!", "But ! Nous avons marqué un but !"),
        ("B", "Fantastisch! Eins zu null!", "Fantastique ! Un à zéro !"),
        ("A", "Möchtest du eine Wurst und ein Wasser?", "Veux-tu une saucisse et une eau ?"),
        ("B", "Ja gern, ich hole sie in der Pause.", "Oui volontiers, je les chercherai à la mi-temps."),
    ]),
    ("À la plage", [
        ("A", "Endlich Strand! Ich liebe das Meer.", "Enfin la plage ! J'adore la mer."),
        ("B", "Das Wasser ist heute warm.", "L'eau est chaude aujourd'hui."),
        ("A", "Hast du die Sonnencreme dabei?", "As-tu la crème solaire ?"),
        ("B", "Ja, sie ist in meiner Tasche.", "Oui, elle est dans mon sac."),
        ("A", "Wir legen uns unter den Sonnenschirm.", "Nous nous allongeons sous le parasol."),
        ("B", "Gute Idee. Die Sonne ist sehr stark.", "Bonne idée. Le soleil est très fort."),
        ("A", "Gehen wir schwimmen?", "Allons-nous nager ?"),
        ("B", "Ja, aber zuerst esse ich eine Banane.", "Oui, mais d'abord je mange une banane."),
        ("A", "Danach spielen wir Volleyball.", "Après nous jouons au volley."),
        ("B", "Super, ich bin dabei!", "Super, je suis partant !"),
    ]),
    ("Le temps qu'il fait", [
        ("A", "Guten Morgen! Wie ist das Wetter heute?", "Bonjour ! Quel temps fait-il aujourd'hui ?"),
        ("B", "Es regnet und es ist kalt.", "Il pleut et il fait froid."),
        ("A", "Wirklich? Gestern war es noch sonnig.", "Vraiment ? Hier il faisait encore beau."),
        ("B", "Ja, aber im Wetterbericht steht Regen.", "Oui, mais la météo annonce de la pluie."),
        ("A", "Wie viel Grad sind es denn?", "Combien de degrés y a-t-il donc ?"),
        ("B", "Nur acht Grad.", "Seulement huit degrés."),
        ("A", "Dann nehme ich meine Jacke mit.", "Alors j'emporte ma veste."),
        ("B", "Vergiss den Regenschirm nicht.", "N'oublie pas le parapluie."),
        ("A", "Und morgen? Wird es besser?", "Et demain ? Est-ce que ce sera mieux ?"),
        ("B", "Ja, morgen scheint wieder die Sonne.", "Oui, demain le soleil brillera de nouveau."),
    ]),
    ("Projets de vacances", [
        ("A", "Was machst du im Sommer, Fatou?", "Que fais-tu cet été, Fatou ?"),
        ("B", "Ich fahre nach Frankreich zu meiner Tante.", "Je vais en France chez ma tante."),
        ("A", "Wie schön! Wie lange bleibst du dort?", "Comme c'est beau ! Combien de temps y restes-tu ?"),
        ("B", "Drei Wochen. Und du?", "Trois semaines. Et toi ?"),
        ("A", "Ich bleibe zu Hause und arbeite.", "Je reste à la maison et je travaille."),
        ("B", "Das ist schade. Hast du keinen Urlaub?", "C'est dommage. N'as-tu pas de congés ?"),
        ("A", "Doch, im Oktober habe ich zwei Wochen frei.", "Si, en octobre j'ai deux semaines de congé."),
        ("B", "Wohin möchtest du dann reisen?", "Où voudrais-tu voyager alors ?"),
        ("A", "Ich möchte nach Spanien fliegen.", "Je voudrais aller en Espagne en avion."),
        ("B", "Das klingt wunderbar. Viel Spaß!", "Cela semble merveilleux. Amuse-toi bien !"),
    ]),
    ("Bagages perdus", [
        ("A", "Entschuldigung, mein Koffer ist nicht da.", "Excusez-moi, ma valise n'est pas là."),
        ("B", "Welchen Flug hatten Sie?", "Quel vol aviez-vous ?"),
        ("A", "Den Flug aus Douala, Nummer vier-sieben-zwei.", "Le vol de Douala, numéro quatre-sept-deux."),
        ("B", "Wie sieht Ihr Koffer aus?", "À quoi ressemble votre valise ?"),
        ("A", "Er ist groß und schwarz.", "Elle est grande et noire."),
        ("B", "Haben Sie den Gepäckschein?", "Avez-vous le bulletin de bagage ?"),
        ("A", "Ja, hier ist er.", "Oui, le voici."),
        ("B", "Wir suchen den Koffer und rufen Sie an.", "Nous cherchons la valise et nous vous appelons."),
        ("A", "Wann bekomme ich ihn?", "Quand l'aurai-je ?"),
        ("B", "Wahrscheinlich morgen, wir bringen ihn zum Hotel.", "Probablement demain, nous l'apportons à l'hôtel."),
    ]),
    ("Objet trouvé", [
        ("A", "Guten Tag, ich habe meine Tasche verloren.", "Bonjour, j'ai perdu mon sac."),
        ("B", "Wo haben Sie sie verloren?", "Où l'avez-vous perdu ?"),
        ("A", "Vielleicht im Bus oder in der Bahn.", "Peut-être dans le bus ou dans le train."),
        ("B", "Wie sieht die Tasche aus?", "À quoi ressemble le sac ?"),
        ("A", "Sie ist braun und klein.", "Il est marron et petit."),
        ("B", "Was war in der Tasche?", "Qu'y avait-il dans le sac ?"),
        ("A", "Mein Schlüssel und ein Buch.", "Ma clé et un livre."),
        ("B", "Moment, ich schaue nach. Ist das Ihre Tasche?", "Un instant, je regarde. Est-ce votre sac ?"),
        ("A", "Ja, das ist sie! Ich bin so froh!", "Oui, c'est lui ! Je suis si content !"),
        ("B", "Bitte schreiben Sie hier Ihren Namen.", "Écrivez votre nom ici, s'il vous plaît."),
    ]),
    ("Déclarer un vol", [
        ("A", "Guten Tag, ich möchte einen Diebstahl melden.", "Bonjour, je voudrais déclarer un vol."),
        ("B", "Was ist passiert?", "Que s'est-il passé ?"),
        ("A", "Jemand hat mein Handy gestohlen.", "Quelqu'un a volé mon téléphone."),
        ("B", "Wann und wo war das?", "Quand et où était-ce ?"),
        ("A", "Heute Mittag auf dem Markt.", "Aujourd'hui à midi au marché."),
        ("B", "Wie sieht das Handy aus?", "À quoi ressemble le téléphone ?"),
        ("A", "Es ist schwarz, mit einer roten Hülle.", "Il est noir, avec une coque rouge."),
        ("B", "Wie ist Ihr Name und Ihre Telefonnummer?", "Quels sont votre nom et votre numéro de téléphone ?"),
        ("A", "Ich heiße Samuel Mbarga, die Nummer ist auf dem Zettel.", "Je m'appelle Samuel Mbarga, le numéro est sur le papier."),
        ("B", "Danke. Wir melden uns, wenn wir etwas finden.", "Merci. Nous vous contactons si nous trouvons quelque chose."),
    ]),
    ("Chez le coiffeur", [
        ("A", "Guten Tag, haben Sie einen Termin?", "Bonjour, avez-vous un rendez-vous ?"),
        ("B", "Nein, leider nicht. Haben Sie Zeit?", "Non, malheureusement pas. Avez-vous du temps ?"),
        ("A", "Ja, setzen Sie sich bitte. Was möchten Sie?", "Oui, asseyez-vous s'il vous plaît. Que désirez-vous ?"),
        ("B", "Die Haare kürzer, bitte.", "Les cheveux plus courts, s'il vous plaît."),
        ("A", "Wie viel soll ich schneiden?", "Combien dois-je couper ?"),
        ("B", "Etwa drei Zentimeter.", "Environ trois centimètres."),
        ("A", "Soll ich auch die Haare waschen?", "Dois-je aussi laver les cheveux ?"),
        ("B", "Ja, bitte. Wie lange dauert es?", "Oui, s'il vous plaît. Combien de temps cela dure-t-il ?"),
        ("A", "Ungefähr eine halbe Stunde.", "Environ une demi-heure."),
        ("B", "Perfekt. Das sieht sehr gut aus!", "Parfait. Ça a l'air très bien !"),
    ]),
    ("À la caisse du supermarché", [
        ("A", "Guten Tag, haben Sie eine Kundenkarte?", "Bonjour, avez-vous une carte de fidélité ?"),
        ("B", "Nein, ich habe keine.", "Non, je n'en ai pas."),
        ("A", "Das macht zusammen dreiundzwanzig Euro vierzig.", "Cela fait en tout vingt-trois euros quarante."),
        ("B", "Kann ich mit Karte bezahlen?", "Puis-je payer par carte ?"),
        ("A", "Ja, stecken Sie die Karte bitte hier ein.", "Oui, insérez votre carte ici, s'il vous plaît."),
        ("B", "Es funktioniert nicht.", "Ça ne marche pas."),
        ("A", "Probieren Sie es bitte noch einmal.", "Essayez encore une fois, s'il vous plaît."),
        ("B", "Jetzt ist es gut. Brauche ich einen Bon?", "Maintenant c'est bon. Ai-je besoin d'un ticket ?"),
        ("A", "Hier ist Ihr Kassenbon.", "Voici votre ticket de caisse."),
        ("B", "Danke, bis zum nächsten Mal!", "Merci, à la prochaine fois !"),
    ]),
    ("Commander une pizza", [
        ("A", "Pizzeria Roma, guten Abend!", "Pizzeria Roma, bonsoir !"),
        ("B", "Guten Abend, ich möchte eine Pizza bestellen.", "Bonsoir, je voudrais commander une pizza."),
        ("A", "Welche Pizza hätten Sie gern?", "Quelle pizza désirez-vous ?"),
        ("B", "Eine Pizza mit Käse und Pilzen.", "Une pizza au fromage et aux champignons."),
        ("A", "Groß oder klein?", "Grande ou petite ?"),
        ("B", "Eine große, bitte.", "Une grande, s'il vous plaît."),
        ("A", "Möchten Sie etwas trinken?", "Voulez-vous quelque chose à boire ?"),
        ("B", "Zwei Limonaden, bitte.", "Deux limonades, s'il vous plaît."),
        ("A", "Das kostet vierzehn Euro. Wie ist Ihre Adresse?", "Cela coûte quatorze euros. Quelle est votre adresse ?"),
        ("B", "Rosenweg fünf, zweiter Stock.", "Rosenweg cinq, deuxième étage."),
    ]),
    ("Une livraison", [
        ("A", "Guten Tag, ich habe ein Paket für Sie.", "Bonjour, j'ai un colis pour vous."),
        ("B", "Für mich? Ich habe nichts bestellt.", "Pour moi ? Je n'ai rien commandé."),
        ("A", "Sind Sie Herr Weiß?", "Êtes-vous Monsieur Weiß ?"),
        ("B", "Nein, Herr Weiß wohnt im Erdgeschoss.", "Non, Monsieur Weiß habite au rez-de-chaussée."),
        ("A", "Ach so, dann klingle ich dort.", "Ah bon, alors je sonne là-bas."),
        ("B", "Er ist heute nicht zu Hause.", "Il n'est pas chez lui aujourd'hui."),
        ("A", "Können Sie das Paket annehmen?", "Pouvez-vous accepter le colis ?"),
        ("B", "Ja, kein Problem. Ich gebe es ihm morgen.", "Oui, pas de problème. Je le lui donne demain."),
        ("A", "Bitte unterschreiben Sie hier.", "Signez ici, s'il vous plaît."),
        ("B", "So, bitte schön. Einen schönen Tag!", "Voilà. Bonne journée !"),
    ]),
    ("Le wifi à la maison", [
        ("A", "Hallo Lena, hast du Internet?", "Salut Lena, as-tu internet ?"),
        ("B", "Ja, wir haben WLAN in der ganzen Wohnung.", "Oui, nous avons le wifi dans tout l'appartement."),
        ("A", "Wie heißt das Netzwerk?", "Comment s'appelle le réseau ?"),
        ("B", "Es heißt Familie Berg.", "Il s'appelle Familie Berg."),
        ("A", "Und das Passwort?", "Et le mot de passe ?"),
        ("B", "Das Passwort steht hinter dem Router.", "Le mot de passe est derrière le routeur."),
        ("A", "Jetzt bin ich verbunden. Danke!", "Maintenant je suis connecté. Merci !"),
        ("B", "Ist das Internet schnell genug?", "Internet est-il assez rapide ?"),
        ("A", "Ja, ich kann ein Video sehen.", "Oui, je peux regarder une vidéo."),
        ("B", "Gut. Ich mache uns einen Tee.", "Bien. Je nous prépare un thé."),
    ]),
    ("Présenter ses parents", [
        ("A", "Mama, Papa, das ist meine Freundin Anna.", "Maman, papa, voici mon amie Anna."),
        ("B", "Guten Tag, Anna! Wir freuen uns.", "Bonjour, Anna ! Nous sommes ravis."),
        ("A", "Guten Tag. Sie haben ein schönes Haus.", "Bonjour. Vous avez une belle maison."),
        ("B", "Danke. Möchtest du etwas essen?", "Merci. Veux-tu manger quelque chose ?"),
        ("A", "Ja, gern. Was gibt es denn?", "Oui, volontiers. Qu'y a-t-il donc ?"),
        ("B", "Meine Mutter kocht heute Reis und Fisch.", "Ma mère cuisine du riz et du poisson aujourd'hui."),
        ("A", "Das riecht wunderbar!", "Ça sent merveilleusement bon !"),
        ("B", "Hast du Geschwister, Anna?", "As-tu des frères et sœurs, Anna ?"),
        ("A", "Ja, ich habe einen Bruder und eine Schwester.", "Oui, j'ai un frère et une sœur."),
        ("B", "Wie schön! Wir haben auch zwei Kinder.", "Comme c'est beau ! Nous avons aussi deux enfants."),
    ]),
    ("Acheter un billet de train", [
        ("A", "Guten Tag, ich möchte eine Fahrkarte nach München.", "Bonjour, je voudrais un billet pour Munich."),
        ("B", "Einfach oder hin und zurück?", "Aller simple ou aller-retour ?"),
        ("A", "Hin und zurück, bitte.", "Aller-retour, s'il vous plaît."),
        ("B", "Wann möchten Sie fahren?", "Quand voulez-vous partir ?"),
        ("A", "Morgen früh, gegen sieben Uhr.", "Demain matin, vers sept heures."),
        ("B", "Der Zug fährt um 7:12 Uhr ab.", "Le train part à 7h12."),
        ("A", "Erste oder zweite Klasse?", "Première ou deuxième classe ?"),
        ("B", "Zweite Klasse, das reicht.", "Deuxième classe, ça suffit."),
        ("A", "Das kostet neunundachtzig Euro.", "Cela coûte quatre-vingt-neuf euros."),
        ("B", "Hier ist meine Karte. Vielen Dank!", "Voici ma carte. Merci beaucoup !"),
    ]),
    ("Louer un vélo", [
        ("A", "Hallo, ich möchte ein Fahrrad mieten.", "Bonjour, je voudrais louer un vélo."),
        ("B", "Gern. Für wie lange?", "Volontiers. Pour combien de temps ?"),
        ("A", "Für einen Tag.", "Pour une journée."),
        ("B", "Das kostet zwölf Euro.", "Cela coûte douze euros."),
        ("A", "Ist ein Helm dabei?", "Un casque est-il compris ?"),
        ("B", "Ja, der Helm ist gratis.", "Oui, le casque est gratuit."),
        ("A", "Ich möchte zum See fahren. Ist es weit?", "Je voudrais aller au lac. Est-ce loin ?"),
        ("B", "Nein, nur zehn Kilometer. Hier ist eine Karte.", "Non, seulement dix kilomètres. Voici une carte."),
        ("A", "Bis wann muss ich das Rad zurückbringen?", "Jusqu'à quand dois-je rapporter le vélo ?"),
        ("B", "Bis achtzehn Uhr, bitte.", "Jusqu'à dix-huit heures, s'il vous plaît."),
    ]),
    ("Au camping", [
        ("A", "Guten Tag, haben Sie noch einen Platz frei?", "Bonjour, avez-vous encore un emplacement libre ?"),
        ("B", "Ja, für ein Zelt oder für ein Wohnmobil?", "Oui, pour une tente ou pour un camping-car ?"),
        ("A", "Für ein Zelt, wir sind zu dritt.", "Pour une tente, nous sommes trois."),
        ("B", "Wie lange möchten Sie bleiben?", "Combien de temps voulez-vous rester ?"),
        ("A", "Vier Nächte, bitte.", "Quatre nuits, s'il vous plaît."),
        ("B", "Das macht achtundvierzig Euro.", "Cela fait quarante-huit euros."),
        ("A", "Gibt es hier warmes Wasser zum Duschen?", "Y a-t-il de l'eau chaude pour la douche ici ?"),
        ("B", "Ja, die Duschen sind neben dem Eingang.", "Oui, les douches sont à côté de l'entrée."),
        ("A", "Dürfen wir abends ein Feuer machen?", "Avons-nous le droit de faire un feu le soir ?"),
        ("B", "Nein, aber es gibt einen Grillplatz.", "Non, mais il y a une aire de barbecue."),
    ]),
]

# --- Vocabulaire supplémentaire ---
VOCAB_EXTRA = [
    ("Personnes", "der Mensch", "l'être humain"),
    ("Personnes", "die Person", "la personne"),
    ("Personnes", "der Freund", "l'ami"),
    ("Personnes", "die Freundin", "l'amie"),
    ("Personnes", "der Herr", "le monsieur"),
    ("Personnes", "der Junge", "le garçon"),
    ("Personnes", "das Mädchen", "la fille"),
    ("Personnes", "der Nachbar", "le voisin"),
    ("Personnes", "der Gast", "l'invité"),
    ("Personnes", "der Chef", "le patron"),
    ("Personnes", "der Kollege", "le collègue"),
    ("Personnes", "die Leute", "les gens"),
    ("Personnes", "der Name", "le nom"),
    ("Personnes", "das Baby", "le bébé"),
    ("Famille", "die Eltern", "les parents"),
    ("Famille", "die Geschwister", "les frères et sœurs"),
    ("Famille", "die Großmutter", "la grand-mère"),
    ("Famille", "der Großvater", "le grand-père"),
    ("Famille", "die Oma", "la mamie"),
    ("Famille", "der Opa", "le papi"),
    ("Famille", "der Onkel", "l'oncle"),
    ("Famille", "die Tante", "la tante"),
    ("Famille", "der Cousin", "le cousin"),
    ("Famille", "die Cousine", "la cousine"),
    ("Famille", "der Neffe", "le neveu"),
    ("Famille", "die Nichte", "la nièce"),
    ("Famille", "der Enkel", "le petit-fils"),
    ("Famille", "der Ehemann", "le mari"),
    ("Famille", "die Ehefrau", "l'épouse"),
    ("Corps humain", "der Körper", "le corps"),
    ("Corps humain", "der Kopf", "la tête"),
    ("Corps humain", "das Gesicht", "le visage"),
    ("Corps humain", "das Auge", "l'œil"),
    ("Corps humain", "das Ohr", "l'oreille"),
    ("Corps humain", "die Nase", "le nez"),
    ("Corps humain", "der Mund", "la bouche"),
    ("Corps humain", "der Zahn", "la dent"),
    ("Corps humain", "das Haar", "le cheveu"),
    ("Corps humain", "der Hals", "le cou"),
    ("Corps humain", "der Arm", "le bras"),
    ("Corps humain", "die Hand", "la main"),
    ("Corps humain", "der Finger", "le doigt"),
    ("Corps humain", "das Bein", "la jambe"),
    ("Corps humain", "der Fuß", "le pied"),
    ("Corps humain", "der Bauch", "le ventre"),
    ("Corps humain", "der Rücken", "le dos"),
    ("Corps humain", "das Herz", "le cœur"),
    ("Corps humain", "das Knie", "le genou"),
    ("Maison", "das Fenster", "la fenêtre"),
    ("Maison", "die Tür", "la porte"),
    ("Maison", "der Garten", "le jardin"),
    ("Maison", "das Schlafzimmer", "la chambre à coucher"),
    ("Maison", "das Wohnzimmer", "le salon"),
    ("Maison", "der Balkon", "le balcon"),
    ("Maison", "die Treppe", "l'escalier"),
    ("Maison", "der Boden", "le sol"),
    ("Maison", "die Wand", "le mur"),
    ("Maison", "das Dach", "le toit"),
    ("Maison", "der Keller", "la cave"),
    ("Maison", "der Flur", "le couloir"),
    ("Maison", "die Toilette", "les toilettes"),
    ("Maison", "die Dusche", "la douche"),
    ("Maison", "der Schlüssel", "la clé"),
    ("Maison", "die Miete", "le loyer"),
    ("Meubles et objets", "der Tisch", "la table"),
    ("Meubles et objets", "der Stuhl", "la chaise"),
    ("Meubles et objets", "das Bett", "le lit"),
    ("Meubles et objets", "der Schrank", "l'armoire"),
    ("Meubles et objets", "das Sofa", "le canapé"),
    ("Meubles et objets", "die Lampe", "la lampe"),
    ("Meubles et objets", "der Spiegel", "le miroir"),
    ("Meubles et objets", "der Teppich", "le tapis"),
    ("Meubles et objets", "das Regal", "l'étagère"),
    ("Meubles et objets", "die Tasche", "le sac"),
    ("Meubles et objets", "das Buch", "le livre"),
    ("Meubles et objets", "der Stift", "le stylo"),
    ("Meubles et objets", "das Papier", "le papier"),
    ("Meubles et objets", "die Flasche", "la bouteille"),
    ("Meubles et objets", "das Glas", "le verre"),
    ("Meubles et objets", "die Tasse", "la tasse"),
    ("Meubles et objets", "der Teller", "l'assiette"),
    ("Meubles et objets", "der Löffel", "la cuillère"),
    ("Meubles et objets", "das Messer", "le couteau"),
    ("Meubles et objets", "die Gabel", "la fourchette"),
    ("Meubles et objets", "der Topf", "la casserole"),
    ("Meubles et objets", "der Kühlschrank", "le réfrigérateur"),
    ("Nourriture", "das Essen", "le repas"),
    ("Nourriture", "das Frühstück", "le petit-déjeuner"),
    ("Nourriture", "das Mittagessen", "le déjeuner"),
    ("Nourriture", "das Abendessen", "le dîner"),
    ("Nourriture", "das Fleisch", "la viande"),
    ("Nourriture", "der Fisch", "le poisson"),
    ("Nourriture", "das Hähnchen", "le poulet"),
    ("Nourriture", "das Ei", "l'œuf"),
    ("Nourriture", "der Käse", "le fromage"),
    ("Nourriture", "die Butter", "le beurre"),
    ("Nourriture", "der Reis", "le riz"),
    ("Nourriture", "die Nudeln", "les pâtes"),
    ("Nourriture", "die Suppe", "la soupe"),
    ("Nourriture", "der Salat", "la salade"),
    ("Nourriture", "der Kuchen", "le gâteau"),
    ("Nourriture", "die Pizza", "la pizza"),
    ("Nourriture", "das Salz", "le sel"),
    ("Nourriture", "der Zucker", "le sucre"),
    ("Nourriture", "die Wurst", "la saucisse"),
    ("Nourriture", "das Öl", "l'huile"),
    ("Nourriture", "die Schokolade", "le chocolat"),
    ("Nourriture", "das Eis", "la glace"),
    ("Boissons", "das Getränk", "la boisson"),
    ("Boissons", "die Milch", "le lait"),
    ("Boissons", "der Saft", "le jus"),
    ("Boissons", "der Orangensaft", "le jus d'orange"),
    ("Boissons", "der Apfelsaft", "le jus de pomme"),
    ("Boissons", "der Wein", "le vin"),
    ("Boissons", "die Cola", "le coca"),
    ("Boissons", "die Limonade", "la limonade"),
    ("Boissons", "das Mineralwasser", "l'eau minérale"),
    ("Boissons", "der Kakao", "le cacao"),
    ("Boissons", "der Sekt", "le vin mousseux"),
    ("Boissons", "der Alkohol", "l'alcool"),
    ("Fruits et légumes", "das Obst", "les fruits"),
    ("Fruits et légumes", "das Gemüse", "les légumes"),
    ("Fruits et légumes", "der Apfel", "la pomme"),
    ("Fruits et légumes", "die Banane", "la banane"),
    ("Fruits et légumes", "die Orange", "l'orange"),
    ("Fruits et légumes", "die Birne", "la poire"),
    ("Fruits et légumes", "die Traube", "le raisin"),
    ("Fruits et légumes", "die Erdbeere", "la fraise"),
    ("Fruits et légumes", "die Zitrone", "le citron"),
    ("Fruits et légumes", "die Kirsche", "la cerise"),
    ("Fruits et légumes", "die Tomate", "la tomate"),
    ("Fruits et légumes", "die Kartoffel", "la pomme de terre"),
    ("Fruits et légumes", "die Zwiebel", "l'oignon"),
    ("Fruits et légumes", "die Karotte", "la carotte"),
    ("Fruits et légumes", "die Gurke", "le concombre"),
    ("Fruits et légumes", "der Knoblauch", "l'ail"),
    ("Vêtements", "die Kleidung", "les vêtements"),
    ("Vêtements", "das Hemd", "la chemise"),
    ("Vêtements", "die Bluse", "le chemisier"),
    ("Vêtements", "die Hose", "le pantalon"),
    ("Vêtements", "das Kleid", "la robe"),
    ("Vêtements", "der Rock", "la jupe"),
    ("Vêtements", "die Jacke", "la veste"),
    ("Vêtements", "der Mantel", "le manteau"),
    ("Vêtements", "der Pullover", "le pull"),
    ("Vêtements", "das T-Shirt", "le tee-shirt"),
    ("Vêtements", "der Anzug", "le costume"),
    ("Vêtements", "der Schuh", "la chaussure"),
    ("Vêtements", "die Socke", "la chaussette"),
    ("Vêtements", "die Mütze", "le bonnet"),
    ("Vêtements", "der Hut", "le chapeau"),
    ("Vêtements", "der Schal", "l'écharpe"),
    ("Vêtements", "die Brille", "les lunettes"),
    ("Couleurs", "die Farbe", "la couleur"),
    ("Couleurs", "rot", "rouge"),
    ("Couleurs", "blau", "bleu"),
    ("Couleurs", "grün", "vert"),
    ("Couleurs", "gelb", "jaune"),
    ("Couleurs", "schwarz", "noir"),
    ("Couleurs", "weiß", "blanc"),
    ("Couleurs", "braun", "marron"),
    ("Couleurs", "grau", "gris"),
    ("Couleurs", "orange", "orange"),
    ("Couleurs", "rosa", "rose"),
    ("Couleurs", "lila", "violet"),
    ("Couleurs", "bunt", "multicolore"),
    ("Animaux", "das Tier", "l'animal"),
    ("Animaux", "der Hund", "le chien"),
    ("Animaux", "die Katze", "le chat"),
    ("Animaux", "der Vogel", "l'oiseau"),
    ("Animaux", "das Pferd", "le cheval"),
    ("Animaux", "die Kuh", "la vache"),
    ("Animaux", "das Schwein", "le cochon"),
    ("Animaux", "das Schaf", "le mouton"),
    ("Animaux", "die Ziege", "la chèvre"),
    ("Animaux", "das Huhn", "la poule"),
    ("Animaux", "die Ente", "le canard"),
    ("Animaux", "die Maus", "la souris"),
    ("Animaux", "der Hase", "le lièvre"),
    ("Animaux", "der Affe", "le singe"),
    ("Animaux", "der Löwe", "le lion"),
    ("Animaux", "der Elefant", "l'éléphant"),
    ("Animaux", "der Bär", "l'ours"),
    ("Animaux", "die Schlange", "le serpent"),
    ("Métiers", "der Beruf", "le métier"),
    ("Métiers", "der Arzt", "le médecin"),
    ("Métiers", "die Ärztin", "la femme médecin"),
    ("Métiers", "der Lehrer", "l'enseignant"),
    ("Métiers", "die Lehrerin", "l'enseignante"),
    ("Métiers", "der Koch", "le cuisinier"),
    ("Métiers", "der Fahrer", "le chauffeur"),
    ("Métiers", "der Polizist", "le policier"),
    ("Métiers", "der Verkäufer", "le vendeur"),
    ("Métiers", "der Ingenieur", "l'ingénieur"),
    ("Métiers", "der Bauer", "l'agriculteur"),
    ("Métiers", "der Friseur", "le coiffeur"),
    ("Métiers", "der Kellner", "le serveur"),
    ("Métiers", "der Bäcker", "le boulanger"),
    ("Métiers", "der Schauspieler", "l'acteur"),
    ("École et études", "die Schule", "l'école"),
    ("École et études", "die Universität", "l'université"),
    ("École et études", "die Klasse", "la classe"),
    ("École et études", "der Schüler", "l'élève"),
    ("École et études", "der Student", "l'étudiant"),
    ("École et études", "der Unterricht", "le cours"),
    ("École et études", "die Prüfung", "l'examen"),
    ("École et études", "die Hausaufgabe", "le devoir"),
    ("École et études", "die Frage", "la question"),
    ("École et études", "die Antwort", "la réponse"),
    ("École et études", "die Tafel", "le tableau"),
    ("École et études", "das Heft", "le cahier"),
    ("École et études", "das Wörterbuch", "le dictionnaire"),
    ("École et études", "die Note", "la note"),
    ("École et études", "die Pause", "la pause"),
    ("École et études", "die Sprache", "la langue"),
    ("École et études", "das Wort", "le mot"),
    ("École et études", "der Satz", "la phrase"),
    ("École et études", "die Übung", "l'exercice"),
    ("Travail et bureau", "die Arbeit", "le travail"),
    ("Travail et bureau", "das Büro", "le bureau"),
    ("Travail et bureau", "die Firma", "l'entreprise"),
    ("Travail et bureau", "die Besprechung", "la réunion"),
    ("Travail et bureau", "der Termin", "le rendez-vous"),
    ("Travail et bureau", "das Gehalt", "le salaire"),
    ("Travail et bureau", "der Vertrag", "le contrat"),
    ("Travail et bureau", "die Stelle", "le poste"),
    ("Travail et bureau", "die Bewerbung", "la candidature"),
    ("Travail et bureau", "der Lebenslauf", "le CV"),
    ("Travail et bureau", "die Fabrik", "l'usine"),
    ("Travail et bureau", "die Maschine", "la machine"),
    ("Travail et bureau", "der Feierabend", "la fin de journée de travail"),
    ("Ville et lieux", "die Stadt", "la ville"),
    ("Ville et lieux", "das Dorf", "le village"),
    ("Ville et lieux", "das Land", "le pays"),
    ("Ville et lieux", "die Straße", "la rue"),
    ("Ville et lieux", "der Platz", "la place"),
    ("Ville et lieux", "die Brücke", "le pont"),
    ("Ville et lieux", "der Park", "le parc"),
    ("Ville et lieux", "die Kirche", "l'église"),
    ("Ville et lieux", "die Moschee", "la mosquée"),
    ("Ville et lieux", "das Rathaus", "la mairie"),
    ("Ville et lieux", "die Post", "la poste"),
    ("Ville et lieux", "die Polizei", "la police"),
    ("Ville et lieux", "der Markt", "le marché"),
    ("Ville et lieux", "das Restaurant", "le restaurant"),
    ("Ville et lieux", "das Café", "le café"),
    ("Ville et lieux", "das Kino", "le cinéma"),
    ("Ville et lieux", "das Museum", "le musée"),
    ("Ville et lieux", "die Bibliothek", "la bibliothèque"),
    ("Ville et lieux", "die Ampel", "le feu de signalisation"),
    ("Ville et lieux", "die Ecke", "le coin"),
    ("Transports", "das Auto", "la voiture"),
    ("Transports", "der Bus", "le bus"),
    ("Transports", "der Zug", "le train"),
    ("Transports", "die Bahn", "le chemin de fer"),
    ("Transports", "die U-Bahn", "le métro"),
    ("Transports", "die Straßenbahn", "le tramway"),
    ("Transports", "das Fahrrad", "le vélo"),
    ("Transports", "das Motorrad", "la moto"),
    ("Transports", "das Taxi", "le taxi"),
    ("Transports", "das Flugzeug", "l'avion"),
    ("Transports", "das Schiff", "le bateau"),
    ("Transports", "der Bahnhof", "la gare"),
    ("Transports", "die Haltestelle", "l'arrêt"),
    ("Transports", "der Flughafen", "l'aéroport"),
    ("Transports", "die Fahrkarte", "le billet de transport"),
    ("Transports", "das Gleis", "la voie"),
    ("Transports", "die Autobahn", "l'autoroute"),
    ("Transports", "der Weg", "le chemin"),
    ("Transports", "der Verkehr", "la circulation"),
    ("Voyage et hôtel", "die Reise", "le voyage"),
    ("Voyage et hôtel", "der Urlaub", "les vacances"),
    ("Voyage et hôtel", "das Hotel", "l'hôtel"),
    ("Voyage et hôtel", "die Rezeption", "la réception"),
    ("Voyage et hôtel", "das Einzelzimmer", "la chambre simple"),
    ("Voyage et hôtel", "das Doppelzimmer", "la chambre double"),
    ("Voyage et hôtel", "die Reservierung", "la réservation"),
    ("Voyage et hôtel", "der Koffer", "la valise"),
    ("Voyage et hôtel", "das Gepäck", "les bagages"),
    ("Voyage et hôtel", "der Reisepass", "le passeport"),
    ("Voyage et hôtel", "der Ausweis", "la carte d'identité"),
    ("Voyage et hôtel", "das Visum", "le visa"),
    ("Voyage et hôtel", "die Grenze", "la frontière"),
    ("Voyage et hôtel", "der Tourist", "le touriste"),
    ("Voyage et hôtel", "die Landkarte", "la carte géographique"),
    ("Voyage et hôtel", "der Strand", "la plage"),
    ("Santé", "die Gesundheit", "la santé"),
    ("Santé", "die Krankheit", "la maladie"),
    ("Santé", "das Krankenhaus", "l'hôpital"),
    ("Santé", "die Apotheke", "la pharmacie"),
    ("Santé", "die Praxis", "le cabinet médical"),
    ("Santé", "das Medikament", "le médicament"),
    ("Santé", "die Tablette", "le comprimé"),
    ("Santé", "das Rezept", "l'ordonnance"),
    ("Santé", "das Fieber", "la fièvre"),
    ("Santé", "die Erkältung", "le rhume"),
    ("Santé", "die Grippe", "la grippe"),
    ("Santé", "der Husten", "la toux"),
    ("Santé", "der Schmerz", "la douleur"),
    ("Santé", "der Unfall", "l'accident"),
    ("Santé", "der Notfall", "l'urgence"),
    ("Nature et météo", "die Natur", "la nature"),
    ("Nature et météo", "das Wetter", "le temps qu'il fait"),
    ("Nature et météo", "die Sonne", "le soleil"),
    ("Nature et météo", "der Mond", "la lune"),
    ("Nature et météo", "der Stern", "l'étoile"),
    ("Nature et météo", "der Himmel", "le ciel"),
    ("Nature et météo", "die Wolke", "le nuage"),
    ("Nature et météo", "der Regen", "la pluie"),
    ("Nature et météo", "der Schnee", "la neige"),
    ("Nature et météo", "der Wind", "le vent"),
    ("Nature et météo", "das Gewitter", "l'orage"),
    ("Nature et météo", "die Temperatur", "la température"),
    ("Nature et météo", "der Berg", "la montagne"),
    ("Nature et météo", "der Fluss", "le fleuve"),
    ("Nature et météo", "der See", "le lac"),
    ("Nature et météo", "das Meer", "la mer"),
    ("Nature et météo", "der Wald", "la forêt"),
    ("Nature et météo", "der Baum", "l'arbre"),
    ("Nature et météo", "die Blume", "la fleur"),
    ("Nature et météo", "die Erde", "la terre"),
    ("Nature et météo", "die Welt", "le monde"),
    ("Nature et météo", "die Luft", "l'air"),
    ("Nature et météo", "das Feuer", "le feu"),
    ("Nature et météo", "die Insel", "l'île"),
    ("Temps (jours, mois, saisons)", "der Montag", "lundi"),
    ("Temps (jours, mois, saisons)", "der Dienstag", "mardi"),
    ("Temps (jours, mois, saisons)", "der Mittwoch", "mercredi"),
    ("Temps (jours, mois, saisons)", "der Donnerstag", "jeudi"),
    ("Temps (jours, mois, saisons)", "der Freitag", "vendredi"),
    ("Temps (jours, mois, saisons)", "der Samstag", "samedi"),
    ("Temps (jours, mois, saisons)", "der Sonntag", "dimanche"),
    ("Temps (jours, mois, saisons)", "der Januar", "janvier"),
    ("Temps (jours, mois, saisons)", "der Februar", "février"),
    ("Temps (jours, mois, saisons)", "der März", "mars"),
    ("Temps (jours, mois, saisons)", "der April", "avril"),
    ("Temps (jours, mois, saisons)", "der Mai", "mai"),
    ("Temps (jours, mois, saisons)", "der Juni", "juin"),
    ("Temps (jours, mois, saisons)", "der Juli", "juillet"),
    ("Temps (jours, mois, saisons)", "der August", "août"),
    ("Temps (jours, mois, saisons)", "der September", "septembre"),
    ("Temps (jours, mois, saisons)", "der Oktober", "octobre"),
    ("Temps (jours, mois, saisons)", "der November", "novembre"),
    ("Temps (jours, mois, saisons)", "der Dezember", "décembre"),
    ("Temps (jours, mois, saisons)", "der Frühling", "le printemps"),
    ("Temps (jours, mois, saisons)", "der Sommer", "l'été"),
    ("Temps (jours, mois, saisons)", "der Herbst", "l'automne"),
    ("Temps (jours, mois, saisons)", "der Winter", "l'hiver"),
    ("Temps (jours, mois, saisons)", "der Tag", "le jour"),
    ("Temps (jours, mois, saisons)", "die Woche", "la semaine"),
    ("Temps (jours, mois, saisons)", "das Wochenende", "le week-end"),
    ("Temps (jours, mois, saisons)", "der Monat", "le mois"),
    ("Temps (jours, mois, saisons)", "das Jahr", "l'année"),
    ("Temps (jours, mois, saisons)", "der Morgen", "le matin"),
    ("Temps (jours, mois, saisons)", "der Mittag", "midi"),
    ("Temps (jours, mois, saisons)", "der Nachmittag", "l'après-midi"),
    ("Temps (jours, mois, saisons)", "der Abend", "le soir"),
    ("Temps (jours, mois, saisons)", "die Nacht", "la nuit"),
    ("Temps (jours, mois, saisons)", "die Uhr", "l'heure, la montre"),
    ("Temps (jours, mois, saisons)", "die Stunde", "l'heure"),
    ("Temps (jours, mois, saisons)", "die Minute", "la minute"),
    ("Temps (jours, mois, saisons)", "die Sekunde", "la seconde"),
    ("Temps (jours, mois, saisons)", "die Zeit", "le temps"),
    ("Temps (jours, mois, saisons)", "das Datum", "la date"),
    ("Temps (jours, mois, saisons)", "der Geburtstag", "l'anniversaire"),
    ("Verbes courants", "sein", "être"),
    ("Verbes courants", "haben", "avoir"),
    ("Verbes courants", "werden", "devenir"),
    ("Verbes courants", "machen", "faire"),
    ("Verbes courants", "gehen", "aller"),
    ("Verbes courants", "kommen", "venir"),
    ("Verbes courants", "sehen", "voir"),
    ("Verbes courants", "essen", "manger"),
    ("Verbes courants", "trinken", "boire"),
    ("Verbes courants", "kaufen", "acheter"),
    ("Verbes courants", "wohnen", "habiter"),
    ("Verbes courants", "arbeiten", "travailler"),
    ("Verbes courants", "lernen", "apprendre"),
    ("Verbes courants", "sprechen", "parler"),
    ("Verbes courants", "heißen", "s'appeler"),
    ("Verbes courants", "lesen", "lire"),
    ("Verbes courants", "schreiben", "écrire"),
    ("Verbes courants", "hören", "entendre"),
    ("Verbes courants", "spielen", "jouer"),
    ("Verbes courants", "fahren", "rouler"),
    ("Verbes courants", "nehmen", "prendre"),
    ("Verbes courants", "geben", "donner"),
    ("Verbes courants", "wissen", "savoir"),
    ("Verbes courants", "können", "pouvoir"),
    ("Verbes courants", "müssen", "devoir"),
    ("Verbes courants", "wollen", "vouloir"),
    ("Verbes courants", "möchten", "aimerais"),
    ("Verbes courants", "sagen", "dire"),
    ("Verbes courants", "fragen", "demander"),
    ("Verbes courants", "antworten", "répondre"),
    ("Verbes courants", "schlafen", "dormir"),
    ("Verbes courants", "lieben", "aimer"),
    ("Verbes courants", "mögen", "apprécier"),
    ("Verbes courants", "brauchen", "avoir besoin de"),
    ("Verbes courants", "finden", "trouver"),
    ("Verbes courants", "bleiben", "rester"),
    ("Verbes courants", "helfen", "aider"),
    ("Verbes courants", "öffnen", "ouvrir"),
    ("Verbes courants", "schließen", "fermer"),
    ("Verbes courants", "bezahlen", "payer"),
    ("Verbes courants", "kochen", "cuisiner"),
    ("Verbes courants", "aufstehen", "se lever"),
    ("Verbes courants", "einkaufen", "faire les courses"),
    ("Verbes courants", "anrufen", "téléphoner"),
    ("Verbes courants", "anfangen", "commencer"),
    ("Verbes courants", "aussteigen", "descendre"),
    ("Verbes courants", "einsteigen", "monter"),
    ("Verbes courants", "mitkommen", "venir avec"),
    ("Verbes courants", "ankommen", "arriver"),
    ("Verbes courants", "abfahren", "partir"),
    ("Verbes courants", "verstehen", "comprendre"),
    ("Verbes courants", "laufen", "courir"),
    ("Verbes courants", "tanzen", "danser"),
    ("Verbes courants", "singen", "chanter"),
    ("Verbes courants", "warten", "attendre"),
    ("Verbes courants", "suchen", "chercher"),
    ("Verbes courants", "denken", "penser"),
    ("Verbes courants", "treffen", "rencontrer"),
    ("Verbes courants", "besuchen", "rendre visite"),
    ("Verbes courants", "schwimmen", "nager"),
    ("Verbes courants", "lachen", "rire"),
    ("Adjectifs", "groß", "grand"),
    ("Adjectifs", "klein", "petit"),
    ("Adjectifs", "gut", "bon"),
    ("Adjectifs", "schlecht", "mauvais"),
    ("Adjectifs", "neu", "nouveau"),
    ("Adjectifs", "alt", "vieux"),
    ("Adjectifs", "jung", "jeune"),
    ("Adjectifs", "schön", "beau"),
    ("Adjectifs", "hässlich", "laid"),
    ("Adjectifs", "schnell", "rapide"),
    ("Adjectifs", "langsam", "lent"),
    ("Adjectifs", "teuer", "cher"),
    ("Adjectifs", "billig", "bon marché"),
    ("Adjectifs", "warm", "chaud"),
    ("Adjectifs", "kalt", "froid"),
    ("Adjectifs", "heiß", "brûlant"),
    ("Adjectifs", "lang", "long"),
    ("Adjectifs", "kurz", "court"),
    ("Adjectifs", "dick", "épais"),
    ("Adjectifs", "dünn", "mince"),
    ("Adjectifs", "müde", "fatigué"),
    ("Adjectifs", "krank", "malade"),
    ("Adjectifs", "gesund", "en bonne santé"),
    ("Adjectifs", "glücklich", "heureux"),
    ("Adjectifs", "traurig", "triste"),
    ("Adjectifs", "freundlich", "aimable"),
    ("Adjectifs", "nett", "gentil"),
    ("Adjectifs", "laut", "bruyant"),
    ("Adjectifs", "leise", "silencieux"),
    ("Adjectifs", "leicht", "léger"),
    ("Adjectifs", "schwer", "lourd"),
    ("Adjectifs", "einfach", "simple"),
    ("Adjectifs", "schwierig", "difficile"),
    ("Adjectifs", "richtig", "correct"),
    ("Adjectifs", "falsch", "faux"),
    ("Adjectifs", "hell", "clair"),
    ("Adjectifs", "dunkel", "sombre"),
    ("Adjectifs", "voll", "plein"),
    ("Adjectifs", "leer", "vide"),
    ("Adjectifs", "sauber", "propre"),
    ("Adjectifs", "schmutzig", "sale"),
    ("Adjectifs", "hungrig", "affamé"),
    ("Adjectifs", "durstig", "assoiffé"),
    ("Adjectifs", "fertig", "prêt"),
    ("Adjectifs", "wichtig", "important"),
    ("Adjectifs", "interessant", "intéressant"),
    ("Adjectifs", "langweilig", "ennuyeux"),
    ("Adjectifs", "reich", "riche"),
    ("Adjectifs", "arm", "pauvre"),
    ("Adjectifs", "stark", "fort"),
    ("Loisirs et sport", "der Sport", "le sport"),
    ("Loisirs et sport", "der Fußball", "le football"),
    ("Loisirs et sport", "das Spiel", "le jeu"),
    ("Loisirs et sport", "der Ball", "le ballon"),
    ("Loisirs et sport", "die Mannschaft", "l'équipe"),
    ("Loisirs et sport", "die Musik", "la musique"),
    ("Loisirs et sport", "das Lied", "la chanson"),
    ("Loisirs et sport", "der Film", "le film"),
    ("Loisirs et sport", "das Hobby", "le loisir"),
    ("Loisirs et sport", "die Freizeit", "le temps libre"),
    ("Loisirs et sport", "das Konzert", "le concert"),
    ("Loisirs et sport", "die Party", "la fête entre amis"),
    ("Loisirs et sport", "das Fest", "la fête"),
    ("Loisirs et sport", "die Gitarre", "la guitare"),
    ("Loisirs et sport", "der Spaziergang", "la promenade"),
    ("Loisirs et sport", "das Foto", "la photo"),
    ("Technologie et communication", "das Handy", "le portable"),
    ("Technologie et communication", "der Computer", "l'ordinateur"),
    ("Technologie et communication", "das Internet", "Internet"),
    ("Technologie et communication", "die E-Mail", "le courriel"),
    ("Technologie et communication", "die Nachricht", "le message"),
    ("Technologie et communication", "das Telefon", "le téléphone"),
    ("Technologie et communication", "die Telefonnummer", "le numéro de téléphone"),
    ("Technologie et communication", "die Adresse", "l'adresse"),
    ("Technologie et communication", "der Fernseher", "la télévision"),
    ("Technologie et communication", "das Radio", "la radio"),
    ("Technologie et communication", "der Bildschirm", "l'écran"),
    ("Technologie et communication", "die Tastatur", "le clavier"),
    ("Technologie et communication", "das Passwort", "le mot de passe"),
    ("Technologie et communication", "der Brief", "la lettre"),
    ("Technologie et communication", "die Zeitung", "le journal"),
    ("Technologie et communication", "der Anruf", "l'appel"),
    ("Argent et magasins", "das Geld", "l'argent"),
    ("Argent et magasins", "der Euro", "l'euro"),
    ("Argent et magasins", "der Preis", "le prix"),
    ("Argent et magasins", "die Bank", "la banque"),
    ("Argent et magasins", "die Kasse", "la caisse"),
    ("Argent et magasins", "das Konto", "le compte"),
    ("Argent et magasins", "die Kreditkarte", "la carte de crédit"),
    ("Argent et magasins", "das Geschäft", "le magasin"),
    ("Argent et magasins", "der Supermarkt", "le supermarché"),
    ("Argent et magasins", "die Bäckerei", "la boulangerie"),
    ("Argent et magasins", "die Rechnung", "la facture"),
    ("Argent et magasins", "das Angebot", "l'offre"),
    ("Argent et magasins", "das Kleingeld", "la monnaie"),
    ("Argent et magasins", "das Portemonnaie", "le porte-monnaie"),
    ("Argent et magasins", "die Tüte", "le sac plastique"),
    ("Argent et magasins", "der Einkauf", "l'achat"),
    ("Argent et magasins", "der Kunde", "le client"),
    ("Mots utiles", "hier", "ici"),
    ("Mots utiles", "dort", "là-bas"),
    ("Mots utiles", "heute", "aujourd'hui"),
    ("Mots utiles", "gestern", "hier"),
    ("Mots utiles", "morgen", "demain"),
    ("Mots utiles", "jetzt", "maintenant"),
    ("Mots utiles", "immer", "toujours"),
    ("Mots utiles", "nie", "jamais"),
    ("Mots utiles", "oft", "souvent"),
    ("Mots utiles", "manchmal", "parfois"),
    ("Mots utiles", "auch", "aussi"),
    ("Mots utiles", "aber", "mais"),
    ("Mots utiles", "oder", "ou"),
    ("Mots utiles", "und", "et"),
    ("Mots utiles", "sehr", "très"),
    ("Mots utiles", "viel", "beaucoup"),
    ("Mots utiles", "wenig", "peu"),
    ("Mots utiles", "links", "à gauche"),
    ("Mots utiles", "rechts", "à droite"),
    ("Mots utiles", "geradeaus", "tout droit"),
    ("Mots utiles", "bitte", "s'il vous plaît"),
    ("Mots utiles", "danke", "merci"),
    ("Mots utiles", "ja", "oui"),
    ("Mots utiles", "nein", "non"),
    ("Mots utiles", "vielleicht", "peut-être"),
    ("Mots utiles", "nicht", "ne pas"),
    ("Mots utiles", "mit", "avec"),
    ("Mots utiles", "ohne", "sans"),
    ("Mots utiles", "wo", "où"),
    ("Mots utiles", "was", "quoi"),
    ("Mots utiles", "wer", "qui"),
    ("Mots utiles", "wie", "comment"),
    ("Mots utiles", "wann", "quand"),
    ("Mots utiles", "warum", "pourquoi"),
    ("Mots utiles", "noch", "encore"),
    ("Mots utiles", "schon", "déjà"),
    ("Mots utiles", "nur", "seulement"),
    ("Mots utiles", "dann", "ensuite"),
    ("Mots utiles", "zusammen", "ensemble"),
    ("Mots utiles", "hallo", "bonjour"),
    ("Mots utiles", "tschüss", "salut"),
    ("Mots utiles", "Entschuldigung", "pardon"),
]

# --- Expressions supplémentaires ---
LESSONS_EXTRA = [
    ("Au restaurant", "Ein Tisch für zwei Personen, bitte.", "Une table pour deux personnes, s'il vous plaît."),
    ("Au restaurant", "Die Speisekarte, bitte.", "La carte, s'il vous plaît."),
    ("Au restaurant", "Was empfehlen Sie?", "Que recommandez-vous ?"),
    ("Au restaurant", "Ich möchte bestellen.", "Je voudrais commander."),
    ("Au restaurant", "Ich nehme die Suppe.", "Je prends la soupe."),
    ("Au restaurant", "Haben Sie vegetarische Gerichte?", "Avez-vous des plats végétariens ?"),
    ("Au restaurant", "Ich bin allergisch gegen Nüsse.", "Je suis allergique aux noix."),
    ("Au restaurant", "Noch ein Wasser, bitte.", "Encore une eau, s'il vous plaît."),
    ("Au restaurant", "Das Essen ist kalt.", "Le plat est froid."),
    ("Au restaurant", "Zusammen oder getrennt?", "Ensemble ou séparément ?"),
    ("Au restaurant", "Stimmt so.", "Gardez la monnaie."),
    ("Au restaurant", "Ist hier noch frei?", "Est-ce encore libre ici ?"),
    ("Au restaurant", "Ich hätte gern ein Bier.", "Je voudrais une bière."),
    ("Au restaurant", "Das war sehr lecker.", "C'était très bon."),
    ("À l'hôtel", "Ich habe ein Zimmer reserviert.", "J'ai réservé une chambre."),
    ("À l'hôtel", "Ich möchte einchecken.", "Je voudrais m'enregistrer."),
    ("À l'hôtel", "Ein Einzelzimmer, bitte.", "Une chambre simple, s'il vous plaît."),
    ("À l'hôtel", "Ein Doppelzimmer mit Bad, bitte.", "Une chambre double avec salle de bains, s'il vous plaît."),
    ("À l'hôtel", "Wie viel kostet das Zimmer pro Nacht?", "Combien coûte la chambre par nuit ?"),
    ("À l'hôtel", "Gibt es WLAN im Zimmer?", "Y a-t-il du wifi dans la chambre ?"),
    ("À l'hôtel", "Wie ist das WLAN-Passwort?", "Quel est le mot de passe du wifi ?"),
    ("À l'hôtel", "Die Dusche ist kaputt.", "La douche est cassée."),
    ("À l'hôtel", "Das Zimmer hat keine Heizung.", "La chambre n'a pas de chauffage."),
    ("À l'hôtel", "Ich brauche noch eine Decke.", "J'ai besoin d'une couverture de plus."),
    ("À l'hôtel", "Können Sie ein Taxi rufen?", "Pouvez-vous appeler un taxi ?"),
    ("À l'hôtel", "Ich möchte auschecken.", "Je voudrais libérer la chambre."),
    ("À l'hôtel", "Zimmer 12, bitte.", "Chambre 12, s'il vous plaît."),
    ("Au téléphone", "Hallo, hier spricht Paul.", "Allô, ici Paul."),
    ("Au téléphone", "Mit wem spreche ich?", "À qui ai-je l'honneur ?"),
    ("Au téléphone", "Einen Moment, bitte.", "Un instant, s'il vous plaît."),
    ("Au téléphone", "Ich möchte Herrn Schmidt sprechen.", "Je voudrais parler à Monsieur Schmidt."),
    ("Au téléphone", "Er ist leider nicht da.", "Il n'est malheureusement pas là."),
    ("Au téléphone", "Kann ich eine Nachricht hinterlassen?", "Puis-je laisser un message ?"),
    ("Au téléphone", "Ich rufe später noch einmal an.", "Je rappellerai plus tard."),
    ("Au téléphone", "Rufst du mich bitte zurück?", "Peux-tu me rappeler, s'il te plaît ?"),
    ("Au téléphone", "Ich kann Sie nicht hören.", "Je ne vous entends pas."),
    ("Au téléphone", "Die Verbindung ist schlecht.", "La connexion est mauvaise."),
    ("Au téléphone", "Könnten Sie lauter sprechen?", "Pourriez-vous parler plus fort ?"),
    ("Au téléphone", "Wie ist deine Telefonnummer?", "Quel est ton numéro de téléphone ?"),
    ("Au téléphone", "Mein Akku ist leer.", "Ma batterie est vide."),
    ("Au téléphone", "Danke für Ihren Anruf.", "Merci de votre appel."),
    ("Demander son chemin", "Entschuldigung, wo ist die Post?", "Excusez-moi, où est la poste ?"),
    ("Demander son chemin", "Ist es weit von hier?", "Est-ce loin d'ici ?"),
    ("Demander son chemin", "Gehen Sie geradeaus.", "Allez tout droit."),
    ("Demander son chemin", "Biegen Sie links ab.", "Tournez à gauche."),
    ("Demander son chemin", "Biegen Sie rechts ab.", "Tournez à droite."),
    ("Demander son chemin", "Die erste Straße links.", "La première rue à gauche."),
    ("Demander son chemin", "Es ist neben der Bank.", "C'est à côté de la banque."),
    ("Demander son chemin", "Es ist gegenüber vom Park.", "C'est en face du parc."),
    ("Demander son chemin", "Es ist hinter dem Supermarkt.", "C'est derrière le supermarché."),
    ("Demander son chemin", "Es ist nicht weit.", "Ce n'est pas loin."),
    ("Demander son chemin", "Gehen Sie bis zur Ampel.", "Allez jusqu'au feu."),
    ("Demander son chemin", "Können Sie mir die Straße auf der Karte zeigen?", "Pouvez-vous me montrer la rue sur la carte ?"),
    ("Demander son chemin", "Ich suche die Touristeninformation.", "Je cherche l'office de tourisme."),
    ("Demander son chemin", "Wie komme ich zum Marktplatz?", "Comment aller à la place du marché ?"),
    ("Au travail", "Ich arbeite von neun bis siebzehn Uhr.", "Je travaille de neuf heures à dix-sept heures."),
    ("Au travail", "Ich habe heute Spätschicht.", "Aujourd'hui, je suis de service du soir."),
    ("Au travail", "Ich habe einen Termin mit dem Chef.", "J'ai un rendez-vous avec le patron."),
    ("Au travail", "Mein Kollege ist krank.", "Mon collègue est malade."),
    ("Au travail", "Ich muss eine E-Mail schreiben.", "Je dois écrire un e-mail."),
    ("Au travail", "Wir haben jetzt Pause.", "Nous avons une pause maintenant."),
    ("Au travail", "Ich mache eine Mittagspause.", "Je fais une pause déjeuner."),
    ("Au travail", "Kannst du mir bitte helfen?", "Peux-tu m'aider, s'il te plaît ?"),
    ("Au travail", "Das Meeting beginnt um zehn Uhr.", "La réunion commence à dix heures."),
    ("Au travail", "Ich habe viel zu tun.", "J'ai beaucoup à faire."),
    ("Au travail", "Ich suche eine Arbeit.", "Je cherche du travail."),
    ("Au travail", "Ich habe morgen frei.", "Demain, je suis en congé."),
    ("Au travail", "Der Drucker funktioniert nicht.", "L'imprimante ne fonctionne pas."),
    ("Au travail", "Ich verdiene nicht viel.", "Je ne gagne pas beaucoup."),
    ("À l'école", "Ich gehe zur Schule.", "Je vais à l'école."),
    ("À l'école", "Ich lerne jeden Tag Deutsch.", "J'apprends l'allemand tous les jours."),
    ("À l'école", "Wir haben heute Unterricht.", "Nous avons cours aujourd'hui."),
    ("À l'école", "Wie schreibt man das Wort?", "Comment écrit-on ce mot ?"),
    ("À l'école", "Ich habe meine Hausaufgaben gemacht.", "J'ai fait mes devoirs."),
    ("À l'école", "Ich habe meinen Stift vergessen.", "J'ai oublié mon stylo."),
    ("À l'école", "Leihst du mir deinen Kugelschreiber?", "Me prêtes-tu ton stylo ?"),
    ("À l'école", "Öffnet das Buch auf Seite zehn.", "Ouvrez le livre à la page dix."),
    ("À l'école", "Die Prüfung ist morgen.", "L'examen est demain."),
    ("À l'école", "Das Wort kenne ich nicht.", "Je ne connais pas ce mot."),
    ("À l'école", "Darf ich bitte hinausgehen?", "Puis-je sortir, s'il vous plaît ?"),
    ("À l'école", "Hören Sie bitte zu.", "Écoutez, s'il vous plaît."),
    ("À l'école", "Mein Lieblingsfach ist Mathe.", "Ma matière préférée est les maths."),
    ("Loisirs", "Was machst du in deiner Freizeit?", "Que fais-tu pendant ton temps libre ?"),
    ("Loisirs", "Ich spiele gern Fußball.", "J'aime jouer au football."),
    ("Loisirs", "Ich lese gern Bücher.", "J'aime lire des livres."),
    ("Loisirs", "Ich tanze sehr gern.", "J'aime beaucoup danser."),
    ("Loisirs", "Ich koche gern mit Freunden.", "J'aime cuisiner avec des amis."),
    ("Loisirs", "Ich gehe oft spazieren.", "Je vais souvent me promener."),
    ("Loisirs", "Hast du ein Hobby?", "As-tu un loisir ?"),
    ("Loisirs", "Ich schwimme jeden Samstag.", "Je nage tous les samedis."),
    ("Loisirs", "Ich sehe gern Filme.", "J'aime regarder des films."),
    ("Loisirs", "Spielst du ein Instrument?", "Joues-tu d'un instrument ?"),
    ("Loisirs", "Ich fahre gern Fahrrad.", "J'aime faire du vélo."),
    ("Loisirs", "Lass uns Karten spielen!", "Jouons aux cartes !"),
    ("Loisirs", "Am Wochenende gehe ich ins Kino.", "Le week-end, je vais au cinéma."),
    ("Voyage", "Ich mache Urlaub in Deutschland.", "Je passe mes vacances en Allemagne."),
    ("Voyage", "Hier ist mein Reisepass.", "Voici mon passeport."),
    ("Voyage", "Ich brauche ein Visum.", "J'ai besoin d'un visa."),
    ("Voyage", "Ich bin Tourist.", "Je suis touriste."),
    ("Voyage", "Ich bleibe eine Woche.", "Je reste une semaine."),
    ("Voyage", "Wo ist die Passkontrolle?", "Où est le contrôle des passeports ?"),
    ("Voyage", "Ich habe nichts zu verzollen.", "Je n'ai rien à déclarer."),
    ("Voyage", "Mein Flug geht um acht Uhr.", "Mon vol part à huit heures."),
    ("Voyage", "Wo ist mein Gepäck?", "Où sont mes bagages ?"),
    ("Voyage", "Ich möchte ein Foto machen.", "Je voudrais prendre une photo."),
    ("Voyage", "Können Sie ein Foto von uns machen?", "Pouvez-vous nous prendre en photo ?"),
    ("Voyage", "Ich möchte die Stadt besichtigen.", "Je voudrais visiter la ville."),
    ("Voyage", "Wann öffnet das Museum?", "Quand ouvre le musée ?"),
    ("Voyage", "Ich brauche einen Stadtplan.", "J'ai besoin d'un plan de la ville."),
    ("Au marché", "Ich möchte ein Kilo Tomaten.", "Je voudrais un kilo de tomates."),
    ("Au marché", "Was kosten die Äpfel?", "Combien coûtent les pommes ?"),
    ("Au marché", "Sind die Bananen frisch?", "Les bananes sont-elles fraîches ?"),
    ("Au marché", "Ich nehme ein halbes Pfund Käse.", "Je prends une demi-livre de fromage."),
    ("Au marché", "Geben Sie mir bitte drei Orangen.", "Donnez-moi trois oranges, s'il vous plaît."),
    ("Au marché", "Haben Sie auch Mangos?", "Avez-vous aussi des mangues ?"),
    ("Au marché", "Das ist alles, danke.", "C'est tout, merci."),
    ("Au marché", "Darf es sonst noch etwas sein?", "Désirez-vous autre chose ?"),
    ("Au marché", "Das Gemüse sieht gut aus.", "Les légumes ont l'air bons."),
    ("Au marché", "Ich brauche eine Tüte.", "J'ai besoin d'un sac."),
    ("Au marché", "Haben Sie Kleingeld?", "Avez-vous de la monnaie ?"),
    ("Au marché", "Ein Stück Brot, bitte.", "Un morceau de pain, s'il vous plaît."),
    ("Au marché", "Der Markt ist samstags geöffnet.", "Le marché est ouvert le samedi."),
    ("Au marché", "Kann ich probieren?", "Puis-je goûter ?"),
    ("Rendez-vous", "Ich möchte einen Termin vereinbaren.", "Je voudrais prendre rendez-vous."),
    ("Rendez-vous", "Haben Sie morgen Zeit?", "Avez-vous le temps demain ?"),
    ("Rendez-vous", "Passt Ihnen Montag um zehn Uhr?", "Lundi à dix heures vous convient-il ?"),
    ("Rendez-vous", "Leider habe ich da keine Zeit.", "Malheureusement, je n'ai pas le temps à ce moment-là."),
    ("Rendez-vous", "Können wir den Termin verschieben?", "Pouvons-nous reporter le rendez-vous ?"),
    ("Rendez-vous", "Ich muss den Termin absagen.", "Je dois annuler le rendez-vous."),
    ("Rendez-vous", "Wir treffen uns um drei Uhr.", "Nous nous retrouvons à quinze heures."),
    ("Rendez-vous", "Ich warte vor dem Eingang.", "J'attends devant l'entrée."),
    ("Rendez-vous", "Ich bin gleich da.", "J'arrive tout de suite."),
    ("Rendez-vous", "Entschuldigung, ich bin spät dran.", "Désolé, je suis en retard."),
    ("Rendez-vous", "Bis morgen!", "À demain !"),
    ("Rendez-vous", "Ich habe einen Termin beim Zahnarzt.", "J'ai un rendez-vous chez le dentiste."),
    ("Sentiments", "Ich bin glücklich.", "Je suis heureux."),
    ("Sentiments", "Ich bin traurig.", "Je suis triste."),
    ("Sentiments", "Ich bin sehr nervös.", "Je suis très nerveux."),
    ("Sentiments", "Ich habe Angst.", "J'ai peur."),
    ("Sentiments", "Ich bin sauer.", "Je suis en colère."),
    ("Sentiments", "Ich freue mich auf morgen.", "Je me réjouis de demain."),
    ("Sentiments", "Mir ist langweilig.", "Je m'ennuie."),
    ("Sentiments", "Mir ist kalt.", "J'ai froid."),
    ("Sentiments", "Mir ist heiß.", "J'ai chaud."),
    ("Sentiments", "Ich bin stolz auf dich.", "Je suis fier de toi."),
    ("Sentiments", "Ich vermisse dich.", "Tu me manques."),
    ("Sentiments", "Ich liebe dich.", "Je t'aime."),
    ("Sentiments", "Das macht mir Spaß.", "Cela me plaît."),
    ("Invitations", "Möchtest du mit mir essen gehen?", "Veux-tu aller manger avec moi ?"),
    ("Invitations", "Ich lade dich zum Essen ein.", "Je t'invite à manger."),
    ("Invitations", "Hast du Lust auf einen Kaffee?", "As-tu envie d'un café ?"),
    ("Invitations", "Kommst du zu meiner Party?", "Viens-tu à ma fête ?"),
    ("Invitations", "Gern, ich komme.", "Avec plaisir, je viens."),
    ("Invitations", "Leider kann ich nicht kommen.", "Malheureusement, je ne peux pas venir."),
    ("Invitations", "Vielen Dank für die Einladung.", "Merci beaucoup pour l'invitation."),
    ("Invitations", "Wir feiern am Samstag.", "Nous faisons la fête samedi."),
    ("Invitations", "Bringst du etwas zu trinken mit?", "Apportes-tu quelque chose à boire ?"),
    ("Invitations", "Herzlichen Glückwunsch zum Geburtstag!", "Joyeux anniversaire !"),
    ("Invitations", "Kommen Sie doch herein.", "Entrez donc."),
    ("Invitations", "Fühl dich wie zu Hause.", "Fais comme chez toi."),
    ("Invitations", "Setzen Sie sich bitte.", "Asseyez-vous, s'il vous plaît."),
    ("Invitations", "Was für eine schöne Überraschung!", "Quelle belle surprise !"),
    ("Excuses", "Entschuldigung!", "Excusez-moi !"),
    ("Excuses", "Es tut mir leid.", "Je suis désolé."),
    ("Excuses", "Das war mein Fehler.", "C'était mon erreur."),
    ("Excuses", "Das macht nichts.", "Ce n'est pas grave."),
    ("Excuses", "Kein Problem.", "Pas de problème."),
    ("Excuses", "Ich habe es nicht gewusst.", "Je ne le savais pas."),
    ("Excuses", "Verzeihung, darf ich vorbei?", "Pardon, puis-je passer ?"),
    ("Excuses", "Entschuldigen Sie die Störung.", "Excusez-moi de vous déranger."),
    ("Excuses", "Das tut mir wirklich leid.", "Je suis vraiment désolé."),
    ("Excuses", "Keine Sorge.", "Ne vous inquiétez pas."),
    ("Excuses", "Ich komme leider zu spät.", "J'arrive malheureusement en retard."),
    ("Excuses", "Das habe ich nicht gewollt.", "Je ne l'ai pas voulu."),
    ("Excuses", "Schon gut.", "C'est bon."),
    ("Banque et poste", "Ich möchte ein Konto eröffnen.", "Je voudrais ouvrir un compte."),
    ("Banque et poste", "Ich möchte Geld wechseln.", "Je voudrais changer de l'argent."),
    ("Banque et poste", "Wie ist der Wechselkurs?", "Quel est le taux de change ?"),
    ("Banque et poste", "Ich möchte Geld überweisen.", "Je voudrais faire un virement."),
    ("Banque et poste", "Ich habe meine PIN vergessen.", "J'ai oublié mon code PIN."),
    ("Banque et poste", "Meine Karte ist gesperrt.", "Ma carte est bloquée."),
    ("Banque et poste", "Wie hoch sind die Gebühren?", "À combien s'élèvent les frais ?"),
    ("Banque et poste", "Ich möchte einen Brief nach Kamerun schicken.", "Je voudrais envoyer une lettre au Cameroun."),
    ("Banque et poste", "Eine Briefmarke, bitte.", "Un timbre, s'il vous plaît."),
    ("Banque et poste", "Wie lange dauert das Paket?", "Combien de temps le colis met-il ?"),
    ("Banque et poste", "Ich möchte ein Paket abholen.", "Je voudrais retirer un colis."),
    ("Banque et poste", "Wo kann ich unterschreiben?", "Où puis-je signer ?"),
    ("Banque et poste", "Hier ist mein Ausweis.", "Voici ma pièce d'identité."),
    ("Banque et poste", "Die Bank schließt um vier Uhr.", "La banque ferme à seize heures."),
    ("Internet et technologie", "Hast du WLAN?", "As-tu du wifi ?"),
    ("Internet et technologie", "Das Internet ist langsam.", "Internet est lent."),
    ("Internet et technologie", "Ich habe kein Netz.", "Je n'ai pas de réseau."),
    ("Internet et technologie", "Ich muss mein Handy aufladen.", "Je dois recharger mon portable."),
    ("Internet et technologie", "Hast du ein Ladekabel?", "As-tu un câble de chargeur ?"),
    ("Internet et technologie", "Schick mir bitte eine Nachricht.", "Envoie-moi un message, s'il te plaît."),
    ("Internet et technologie", "Wie ist deine E-Mail-Adresse?", "Quelle est ton adresse e-mail ?"),
    ("Internet et technologie", "Mein Computer startet nicht.", "Mon ordinateur ne démarre pas."),
    ("Internet et technologie", "Ich habe die Datei gespeichert.", "J'ai enregistré le fichier."),
    ("Internet et technologie", "Wir machen einen Videoanruf.", "Nous faisons un appel vidéo."),
    ("Internet et technologie", "Ich lade die App herunter.", "Je télécharge l'application."),
    ("Internet et technologie", "Das Passwort ist falsch.", "Le mot de passe est faux."),
    ("Internet et technologie", "Mach bitte das Handy aus.", "Éteins ton portable, s'il te plaît."),
    ("Internet et technologie", "Ich schreibe dir auf WhatsApp.", "Je t'écris sur WhatsApp."),
    ("Santé", "Ich habe Husten.", "Je tousse."),
    ("Santé", "Wo ist die nächste Apotheke?", "Où est la pharmacie la plus proche ?"),
    ("Santé", "Ich brauche Tabletten gegen Schmerzen.", "J'ai besoin de comprimés contre la douleur."),
    ("Santé", "Der Arzt hat heute geöffnet.", "Le médecin est ouvert aujourd'hui."),
    ("Santé", "Mir ist schlecht.", "J'ai mal au cœur."),
    ("Santé", "Ich muss mich ausruhen.", "Je dois me reposer."),
    ("Santé", "Trinken Sie viel Wasser.", "Buvez beaucoup d'eau."),
    ("Urgences", "Ich brauche sofort Hilfe!", "J'ai besoin d'aide tout de suite !"),
    ("Urgences", "Es gab einen Unfall.", "Il y a eu un accident."),
    ("Urgences", "Mein Portemonnaie wurde gestohlen.", "On m'a volé mon portefeuille."),
    ("Urgences", "Feuer!", "Au feu !"),
    ("Urgences", "Ich habe mich verletzt.", "Je me suis blessé."),
    ("Politesse", "Gern geschehen.", "Avec plaisir."),
    ("Politesse", "Bitte sehr.", "Voilà, je vous en prie."),
    ("Politesse", "Viel Glück!", "Bonne chance !"),
    ("Politesse", "Schönen Tag noch!", "Bonne journée !"),
    ("Politesse", "Schönes Wochenende!", "Bon week-end !"),
    ("Météo", "Heute scheint die Sonne.", "Aujourd'hui, il y a du soleil."),
    ("Météo", "Es ist sehr heiß heute.", "Il fait très chaud aujourd'hui."),
    ("Météo", "Morgen schneit es.", "Demain, il neige."),
    ("Météo", "Es ist windig und kalt.", "Il y a du vent et il fait froid."),
    ("Temps", "Ich stehe um sechs Uhr auf.", "Je me lève à six heures."),
    ("Temps", "Es ist halb drei.", "Il est deux heures et demie."),
    ("Temps", "Ich habe keine Zeit.", "Je n'ai pas le temps."),
    ("Temps", "Ich komme morgen früh.", "Je viens demain matin."),
    ("Temps", "Heute ist Montag.", "Aujourd'hui, c'est lundi."),
    ("Maison", "Ich wohne in einer kleinen Wohnung.", "J'habite dans un petit appartement."),
    ("Maison", "Ich muss die Wäsche waschen.", "Je dois faire la lessive."),
    ("Maison", "Kannst du bitte den Müll rausbringen?", "Peux-tu sortir les poubelles, s'il te plaît ?"),
    ("Famille", "Mein Vater arbeitet als Fahrer.", "Mon père travaille comme chauffeur."),
    ("Famille", "Meine Mutter kocht sehr gut.", "Ma mère cuisine très bien."),
    ("Famille", "Hast du Geschwister?", "As-tu des frères et sœurs ?"),
]

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
    _sync_lessons(cursor, data)

def seed_wfragen(cursor):
    data = [
        ("W-Fragen", "Wer ist das?", "Qui est-ce ?"), ("W-Fragen", "Wer kommt heute?", "Qui vient aujourd'hui ?"),
        ("W-Fragen", "Wer hat das gesagt?", "Qui a dit ça ?"), ("W-Fragen", "Wer wohnt hier?", "Qui habite ici ?"),
        ("W-Fragen", "Wer sind Sie?", "Qui êtes-vous ?"), ("W-Fragen", "Wer ist dein Lehrer?", "Qui est ton professeur ?"),
        ("W-Fragen", "Wer hat Zeit?", "Qui a le temps ?"), ("W-Fragen", "Wer ist müde?", "Qui est fatigué ?"),
        ("W-Fragen", "Wer kocht das Essen?", "Qui cuisine le repas ?"), ("W-Fragen", "Wer arbeitet hier?", "Qui travaille ici ?"),
        ("W-Fragen", "Was machst du?", "Que fais-tu ?"), ("W-Fragen", "Was ist das?", "Qu'est-ce que c'est ?"),
        ("W-Fragen", "Was möchtest du trinken?", "Que veux-tu boire ?"), ("W-Fragen", "Was kostet das Buch?", "Combien coûte le livre ?"),
        ("W-Fragen", "Was ist dein Name?", "Quel est ton nom ?"), ("W-Fragen", "Was isst du gern?", "Qu'est-ce que tu aimes manger ?"),
        ("W-Fragen", "Was machst du heute Abend?", "Que fais-tu ce soir ?"), ("W-Fragen", "Was ist passiert?", "Que s'est-il passé ?"),
        ("W-Fragen", "Was brauchst du?", "De quoi as-tu besoin ?"), ("W-Fragen", "Was hast du gesagt?", "Qu'as-tu dit ?"),
        ("W-Fragen", "Wo wohnst du?", "Où habites-tu ?"), ("W-Fragen", "Wo ist die Toilette?", "Où sont les toilettes ?"),
        ("W-Fragen", "Wo ist der Bahnhof?", "Où est la gare ?"), ("W-Fragen", "Wo ist das Hotel?", "Où est l'hôtel ?"),
        ("W-Fragen", "Wo arbeitest du?", "Où travailles-tu ?"), ("W-Fragen", "Wo ist mein Schlüssel?", "Où est ma clé ?"),
        ("W-Fragen", "Wo kann ich parken?", "Où puis-je me garer ?"), ("W-Fragen", "Wo ist die Apotheke?", "Où est la pharmacie ?"),
        ("W-Fragen", "Wo ist der Supermarkt?", "Où est le supermarché ?"), ("W-Fragen", "Wo treffen wir uns?", "Où nous retrouvons-nous ?"),
        ("W-Fragen", "Wann kommst du?", "Quand viens-tu ?"), ("W-Fragen", "Wann fängt der Kurs an?", "Quand commence le cours ?"),
        ("W-Fragen", "Wann fährt der Zug?", "Quand part le train ?"), ("W-Fragen", "Wann hast du Geburtstag?", "Quand est ton anniversaire ?"),
        ("W-Fragen", "Wann ist das Frühstück?", "À quelle heure est le petit-déjeuner ?"), ("W-Fragen", "Wann gehen wir ins Kino?", "Quand allons-nous au cinéma ?"),
        ("W-Fragen", "Wann bist du fertig?", "Quand as-tu fini ?"), ("W-Fragen", "Wann öffnet das Geschäft?", "Quand ouvre le magasin ?"),
        ("W-Fragen", "Wann kommt der Bus?", "Quand arrive le bus ?"), ("W-Fragen", "Wann sehen wir uns wieder?", "Quand nous reverrons-nous ?"),
        ("W-Fragen", "Warum lernst du Deutsch?", "Pourquoi apprends-tu l'allemand ?"), ("W-Fragen", "Warum kommst du zu spät?", "Pourquoi viens-tu en retard ?"),
        ("W-Fragen", "Warum ist das so teuer?", "Pourquoi est-ce si cher ?"), ("W-Fragen", "Warum bist du traurig?", "Pourquoi es-tu triste ?"),
        ("W-Fragen", "Warum lachst du?", "Pourquoi ris-tu ?"), ("W-Fragen", "Warum nicht?", "Pourquoi pas ?"),
        ("W-Fragen", "Warum ist die Tür zu?", "Pourquoi la porte est-elle fermée ?"), ("W-Fragen", "Warum hast du keine Zeit?", "Pourquoi n'as-tu pas le temps ?"),
        ("W-Fragen", "Warum fragst du?", "Pourquoi demandes-tu ?"), ("W-Fragen", "Warum arbeitest du heute?", "Pourquoi travailles-tu aujourd'hui ?"),
        ("W-Fragen", "Wie heißt du?", "Comment t'appelles-tu ?"), ("W-Fragen", "Wie geht es dir?", "Comment vas-tu ?"),
        ("W-Fragen", "Wie alt bist du?", "Quel âge as-tu ?"), ("W-Fragen", "Wie kommt ich zum Bahnhof?", "Comment aller à la gare ?"),
        ("W-Fragen", "Wie viel kostet das?", "Combien cela coûte-t-il ?"), ("W-Fragen", "Wie spät ist es?", "Quelle heure est-il ?"),
        ("W-Fragen", "Wie ist das Wetter?", "Quel temps fait-il ?"), ("W-Fragen", "Wie schreibt man das?", "Comment cela s'écrit-il ?"),
        ("W-Fragen", "Wie sagt man das auf Deutsch?", "Comment dit-on cela en allemand ?"), ("W-Fragen", "Wie lange dauert das?", "Combien de temps cela dure-t-il ?"),
        ("W-Fragen", "Woher kommst du?", "D'où viens-tu ?"), ("W-Fragen", "Woher hast du das?", "D'où tiens-tu cela ?"),
        ("W-Fragen", "Woher weißt du das?", "Comment le sais-tu ?"), ("W-Fragen", "Woher kommt dieser Zug?", "D'où vient ce train ?"),
        ("W-Fragen", "Woher sind Sie?", "D'où êtes-vous ?"), ("W-Fragen", "Woher hast du dieses Buch?", "D'où as-tu ce livre ?"),
        ("W-Fragen", "Woher kommt der Lärm?", "D'où vient le bruit ?"), ("W-Fragen", "Woher kennen wir uns?", "D'où nous connaissons-nous ?"),
        ("W-Fragen", "Woher kommt das Wasser?", "D'où vient l'eau ?"), ("W-Fragen", "Woher hast du die Information?", "D'où tiens-tu l'information ?"),
        ("W-Fragen", "Wohin gehst du?", "Où vas-tu ?"), ("W-Fragen", "Wohin fährst du im Urlaub?", "Où vas-tu en vacances ?"),
        ("W-Fragen", "Wohin legst du das Buch?", "Où mets-tu le livre ?"), ("W-Fragen", "Wohin gehen wir heute Abend?", "Où allons-nous ce soir ?"),
        ("W-Fragen", "Wohin fährt dieser Bus?", "Où va ce bus ?"), ("W-Fragen", "Wohin hast du es gelegt?", "Où l'as-tu mis ?"),
        ("W-Fragen", "Wohin läufst du?", "Où cours-tu ?"), ("W-Fragen", "Wohin stellst du die Flasche?", "Où poses-tu la bouteille ?"),
        ("W-Fragen", "Wohin reist du?", "Où voyages-tu ?"), ("W-Fragen", "Wohin geht ihr?", "Où allez-vous ?"),
    ]
    
    _sync_lessons(cursor, data)

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
    _sync_vocab(cursor, vocab)

def seed_lessons_extra(cursor):
    _sync_lessons(cursor, LESSONS_EXTRA)

def seed_vocab_extra(cursor):
    _sync_vocab(cursor, VOCAB_EXTRA)

def seed_dialogues(cursor):
    existing = {r[0]: (r[1], r[2]) for r in cursor.execute("SELECT title, id, lines_json FROM dialogues").fetchall()}
    for title, lines in DIALOGUES_DATA:
        lines_json = json.dumps([{"spk": s, "de": d, "fr": f} for s, d, f in lines])
        if title in existing:
            if existing[title][1] != lines_json:
                cursor.execute("UPDATE dialogues SET lines_json=? WHERE id=?", (lines_json, existing[title][0]))
        else:
            cursor.execute("INSERT INTO dialogues(title, lines_json) VALUES(?, ?)", (title, lines_json))

def seed_numbers(cursor):
    # Les anciennes lignes contenaient des chiffres (« 5 » en français comme en allemand) : on les
    # remplace par de vrais mots, puis on ajoute ceux qui manquent.
    for i, (de, fr) in enumerate(NUMBER_WORDS):
        cursor.execute("UPDATE vocab SET german=?, french=? WHERE category='Nombres' AND german=?",
                       (de, fr, str(i)))
    existing = {r[0] for r in cursor.execute("SELECT german FROM vocab WHERE category='Nombres'").fetchall()}
    for de, fr in NUMBER_WORDS:
        if de not in existing:
            cursor.execute("INSERT INTO vocab(category, german, french) VALUES(?,?,?)", ("Nombres", de, fr))


# =========================================================
# SEED "APPRENDRE À PARLER" (260 phrases complètes)
# =========================================================
SPEAK_PHRASES_DATA = [
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
        ("Je travaille dans un hôpital.", "Ich arbeite in einem Krankenhaus."),
        ("Je suis en première année.", "Ich bin im ersten Studienjahr."),
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
        ("Je suis d'accord.", "Ich bin einverstanden."),
        ("Tu as raison.", "Du hast recht."),
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
# SEED "LES ESSENTIELS A1"
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
            """INSERT INTO essentials_cards(fiche_num, title, content, explanation) VALUES(?,?,?,?)
               ON CONFLICT(fiche_num) DO UPDATE SET title=excluded.title, content=excluded.content,
               explanation=excluded.explanation
               WHERE title!=excluded.title OR content!=excluded.content OR explanation!=excluded.explanation""",
            (num, title, content, explanation)
        )

# =========================================================
# SEED "NOM/AKK"
# =========================================================
NOMAKK_DATA = [
    (1, "La technique la plus simple : QUI ? et QUI/QUOI ?",
     "Le Nominatif désigne généralement la personne ou la chose qui fait l'action : le sujet.\n\n"
     "Exemples :\nDer Mann schläft. = L'homme dort.\nDie Frau lernt. = La femme étudie.\nDas Kind spielt. = L'enfant joue.\n\n"
     "Pose-toi la question : QUI dort ? QUI étudie ? QUI joue ?\n\n"
     "À retenir : le sujet est au Nominatif.\n\n"
     "L'Akkusativ désigne généralement la personne ou la chose sur laquelle porte directement l'action.\n\n"
     "Exemples :\nIch sehe den Mann. = Je vois l'homme.\nIch sehe die Frau. = Je vois la femme.\nIch sehe das Kind. = Je vois l'enfant.\n\n"
     "Pose-toi deux questions :\n1. Qui fait l'action ? → Ich = je.\n2. Je vois qui ? → den Mann = l'homme.\n\n"
     "Le sujet reste au Nominatif, tandis que le complément direct est à l'Akkusativ.",
     "Règle d'or : QUI fait l'action → Nominatif. QUI/QUOI reçoit l'action → Akkusativ."),
    (2, "Le tableau magique pour retenir les articles",
     "Masculin : der → den\nFéminin : die → die\nNeutre : das → das\nPluriel : die → die\n\n"
     "Au masculin, der devient den à l'Akkusativ.\n"
     "Mémorise : DER → DEN ; DIE → DIE ; DAS → DAS ; DIE → DIE.",
     "Un seul changement : der → den au masculin Akkusativ."),
    (3, "Quand utiliser EIN, EINE et EINEN ?",
     "Masculin : ein → einen\nFéminin : eine → eine\nNeutre : ein → ein\nPluriel : pas d'article indéfini\n\n"
     "Ein Mann kommt. = Un homme arrive.\nIch sehe einen Hund. = Je vois un chien.",
     "ein → einen UNIQUEMENT au masculin Akkusativ. eine et ein ne changent jamais."),
    (4, "Et avec KEIN, KEINE, KEINEN ?",
     "Masculin : kein → keinen\nFéminin : keine → keine\nNeutre : kein → kein\nPluriel : keine → keine\n\n"
     "Ich habe einen Hund. ↔ Ich habe keinen Hund.\nIch sehe eine Frau. ↔ Ich sehe keine Frau.",
     "kein → keinen au masculin Akkusativ, exactement comme ein → einen."),
    (5, "Comment savoir si un nom est DER, DIE ou DAS ?",
     "DER : der Mann, der Vater, der Bruder, der Hund\nDIE : die Frau, die Mutter, die Schwester, die Schule\nDAS : das Kind, das Haus, das Auto, das Buch\n\n"
     "Astuces : -ung, -heit, -keit → féminin. -chen, -lein → neutre. -ismus → masculin.",
     "Apprends toujours le nom avec son article."),
    (6, "La méthode en trois étapes",
     "Étape 1 : trouve le sujet (Qui fait l'action ?)\nÉtape 2 : cherche le complément direct (L'action porte sur qui/quoi ?)\nÉtape 3 : identifie le genre du nom\n\n"
     "Exemple : Ich kaufe einen Apfel.\n1. Qui achète ? → Ich.\n2. J'achète quoi ? → Apfel.\n3. Apfel est masculin : der Apfel.\n4. Masculin Akkusativ : einen Apfel.",
     "Méthode : sujet (Nom), complément direct (Akk), genre du nom."),
    (7, "Attention : tous les compléments ne sont pas à l'Akkusativ",
     "Certains verbes prennent le datif :\nIch helfe dem Mann. = J'aide l'homme.\n\n"
     "Verbes A1 à l'Akkusativ : sehen, haben, kaufen, brauchen, essen, trinken.",
     "Au niveau A1, concentre-toi sur les verbes qui prennent l'Akkusativ."),
    (8, "Ton résumé à mémoriser",
     "Masculin : der/den | ein/einen | kein/keinen\nFéminin : die/die | eine/eine | keine/keine\nNeutre : das/das | ein/ein | kein/kein\nPluriel : die/die | — | keine/keine",
     "Retiens juste : au masculin Akkusativ, der→den, ein→einen, kein→keinen."),
    (9, "Petit exercice pour vérifier que tu as compris",
     "1. ___ Mann trinkt Wasser. → Der\n2. Ich sehe ___ Hund. → einen\n3. Sie kauft ___ Tasche. → eine\n4. Er hat ___ Auto. → kein\n5. Ich habe ___ Bruder. → keinen\n6. ___ Frau lernt Deutsch. → Eine\n7. Ich sehe ___ Mann. → den\n8. Er hat ___ Schwester. → keine",
     "Fais l'exercice sans regarder les réponses. Vérifie chaque justification avec la règle QUI/QUOI."),
]

def seed_nomakk_sections(cursor):
    for num, title, content, explanation in NOMAKK_DATA:
        cursor.execute(
            """INSERT INTO nomakk_sections(sec_num, title, content, explanation) VALUES(?,?,?,?)
               ON CONFLICT(sec_num) DO UPDATE SET title=excluded.title, content=excluded.content,
               explanation=excluded.explanation
               WHERE title!=excluded.title OR content!=excluded.content OR explanation!=excluded.explanation""",
            (num, title, content, explanation)
        )

def seed_nomakk_playlist(cursor):
    items = []
    for num, title, content, explanation in NOMAKK_DATA:
        items.append({"fr": f"Section {num} : {title}", "de": f"Abschnitt {num}: {title}"})
        for line in content.split("\n"):
            line = line.strip()
            if "=" in line and "→" not in line and "|" not in line:
                left, right = line.split("=", 1)
                fr_part = left.strip()
                de_part = right.strip()
                if fr_part and de_part and len(fr_part) < 200 and len(de_part) < 200:
                    items.append({"fr": fr_part, "de": de_part})
    payload = json.dumps(items, ensure_ascii=False)
    cursor.execute(
        """INSERT INTO nomakk_playlist(key, title, items_json) VALUES(?,?,?)
           ON CONFLICT(key) DO UPDATE SET title=excluded.title, items_json=excluded.items_json
           WHERE title!=excluded.title OR items_json!=excluded.items_json""",
        ("all", "NOM/AKK — Nominatif vs Akkusativ", payload)
    )

def seed_speak_playlists(cursor):
    for theme_order, (theme, items) in enumerate(SPEAK_PHRASES_DATA, start=1):
        payload = json.dumps([{"fr": fr, "de": de} for fr, de in items], ensure_ascii=False)
        cursor.execute(
            """INSERT INTO speak_playlists(kind, key, title, items_json) VALUES(?,?,?,?)
            ON CONFLICT(kind, key) DO UPDATE SET title=excluded.title, items_json=excluded.items_json
            WHERE title!=excluded.title OR items_json!=excluded.items_json""",
            ("speak", theme, theme, payload)
        )
    essentials_items = []
    for num, title, content, explanation in ESSENTIALS_DATA:
        for line in content.split("\n"):
            if "=" in line:
                left, right = line.split("=", 1)
                essentials_items.append({
                    "fr": left.strip(),
                    "de": right.strip()
                })
    payload = json.dumps(essentials_items, ensure_ascii=False)
    cursor.execute(
        """INSERT INTO speak_playlists(kind, key, title, items_json) VALUES(?,?,?,?)
            ON CONFLICT(kind, key) DO UPDATE SET title=excluded.title, items_json=excluded.items_json
            WHERE title!=excluded.title OR items_json!=excluded.items_json""",
        ("essentials", "all", "Les essentiels A1", payload)
    )

# =========================================================
# === NEFERTI : SEED DES SCÉNARIOS (49 étapes) ===
# 10 catégories, multi-embranchements, mémoire par user.
# =========================================================
NEFERTI_SCENARIOS = [
    # --- Catégorie 1 : SE PRÉSENTER ---
    ("Se présenter", "intro_1",
     "Hallo! Ich bin Neferti. Wie heißt du?",
     "Bonjour ! Je suis Neferti. Comment t'appelles-tu ?",
     "Ich heiße", "heiße,heisse,name,bin",
     "present_name", "present_name", "name", 1),
    ("Se présenter", "present_name",
     "Freut mich, dich kennenzulernen! Wie alt bist du?",
     "Enchantée de te connaître ! Quel âge as-tu ?",
     "Ich bin ... Jahre alt", "jahre,alt,bin",
     "present_city", "present_city", "age", 2),
    ("Se présenter", "present_city",
     "Super! Und woher kommst du?",
     "Super ! Et d'où viens-tu ?",
     "Ich komme aus ...", "komme,aus,land",
     "present_city2", "present_city2", "country", 3),
    ("Se présenter", "present_city2",
     "Interessant! Und wo wohnst du jetzt?",
     "Intéressant ! Et où habites-tu maintenant ?",
     "Ich wohne in ...", "wohne,in,stadt",
     "present_job", "present_job", "city", 4),
    ("Se présenter", "present_job",
     "Ah, schön! Was machst du beruflich? Bist du Student oder arbeitest du?",
     "Ah, bien ! Que fais-tu comme métier ? Es-tu étudiant ou travailles-tu ?",
     "Ich bin Student / Ich arbeite als ...", "student,arbeite,beruf",
     "present_hobby", "present_hobby", "job", 5),
    ("Se présenter", "present_hobby",
     "Toll! Was machst du gern in deiner Freizeit?",
     "Génial ! Que fais-tu volontiers pendant ton temps libre ?",
     "Ich ... gern", "gern,freizeit,hobby",
     "present_language", "present_language", "hobby", 6),
    ("Se présenter", "present_language",
     "Sehr gut! Welche Sprachen sprichst du?",
     "Très bien ! Quelles langues parles-tu ?",
     "Ich spreche ...", "spreche,sprachen,deutsch,französisch",
     "present_finish", "present_finish", "languages", 7),
    ("Se présenter", "present_finish",
     "Wunderbar! Du hast dich super vorgestellt. Möchtest du weiter üben?",
     "Merveilleux ! Tu t'es super bien présenté(e). Veux-tu continuer à t'entraîner ?",
     "Ja / Nein", "ja,nein,gerne,weiter",
     "family_1", "free_1", "", 8),

    # --- Catégorie 2 : FAMILLE ---
    ("Famille", "family_1",
     "Erzähl mir von deiner Familie. Hast du Geschwister?",
     "Parle-moi de ta famille. As-tu des frères et sœurs ?",
     "Ich habe ... Bruder / Schwester", "bruder,schwester,geschwister,habe",
     "family_2", "family_2", "siblings", 9),
    ("Famille", "family_2",
     "Ah, schön! Hast du Kinder?",
     "Ah, bien ! As-tu des enfants ?",
     "Ja, ich habe ... Kinder / Nein, ich habe keine Kinder", "kinder,habe,ja,nein",
     "family_3", "family_3", "children", 10),
    ("Famille", "family_3",
     "Und deine Eltern? Wo wohnen sie?",
     "Et tes parents ? Où habitent-ils ?",
     "Sie wohnen in ...", "eltern,wohnen,mutter,vater",
     "family_4", "family_4", "parents_city", 11),
    ("Famille", "family_4",
     "Sehr schön! Hast du ein Haustier?",
     "Très bien ! As-tu un animal de compagnie ?",
     "Ja, ich habe einen Hund / eine Katze", "haustier,hund,katze,habe",
     "animal_1", "animal_no", "pet", 12),

    # --- Catégorie 3 : ANIMAUX ---
    ("Animaux", "animal_1",
     "Erzähl mir von deinem Haustier! Wie heißt es?",
     "Parle-moi de ton animal ! Comment s'appelle-t-il ?",
     "Er / Sie heißt ...", "heißt,name,hund,katze",
     "animal_2", "animal_2", "pet_name", 13),
    ("Animaux", "animal_2",
     "Wie alt ist dein Haustier?",
     "Quel âge a ton animal ?",
     "Er / Sie ist ... Jahre alt", "jahre,alt,ist",
     "animal_3", "animal_3", "pet_age", 14),
    ("Animaux", "animal_3",
     "Was frisst dein Haustier gern?",
     "Que mange volontiers ton animal ?",
     "Er / Sie frisst ...", "frisst,isst,futter",
     "animal_4", "animal_4", "pet_food", 15),
    ("Animaux", "animal_4",
     "Süß! Magst du auch andere Tiere?",
     "Mignon ! Aimes-tu aussi d'autres animaux ?",
     "Ja, ich mag ... / Nein, ich mag ...", "mag,tiere,ja,nein",
     "animal_5", "animal_5", "fav_animal", 16),
    ("Animaux", "animal_5",
     "Toll! Welches Tier magst du nicht?",
     "Génial ! Quel animal n'aimes-tu pas ?",
     "Ich mag ... nicht", "mag,nicht,tier",
     "food_1", "food_1", "", 17),
    ("Animaux", "animal_no",
     "Kein Problem! Welches Tier magst du am liebsten?",
     "Pas de problème ! Quel animal préfères-tu ?",
     "Ich mag ... am liebsten", "mag,tier,liebsten",
     "animal_5", "animal_5", "fav_animal", 18),

    # --- Catégorie 4 : NOURRITURE ---
    ("Nourriture", "food_1",
     "Jetzt über Essen! Was isst du gern?",
     "Maintenant parlons nourriture ! Qu'aimes-tu manger ?",
     "Ich esse gern ...", "esse,gern,isst",
     "food_2", "food_2", "fav_food", 19),
    ("Nourriture", "food_2",
     "Lecker! Was trinkst du gern?",
     "Délicieux ! Que bois-tu volontiers ?",
     "Ich trinke gern ...", "trinke,gern,getränk",
     "food_3", "food_3", "fav_drink", 20),
    ("Nourriture", "food_3",
     "Kannst du kochen?",
     "Sais-tu cuisiner ?",
     "Ja, ich kann kochen / Nein, ich kann nicht kochen", "kochen,kann,ja,nein",
     "food_4", "food_4", "can_cook", 21),
    ("Nourriture", "food_4",
     "Was ist dein Lieblingsessen?",
     "Quel est ton plat préféré ?",
     "Mein Lieblingsessen ist ...", "lieblingsessen,essen",
     "food_5", "food_5", "fav_dish", 22),
    ("Nourriture", "food_5",
     "Interessant! Isst du auch deutsche Spezialitäten?",
     "Intéressant ! Manges-tu aussi des spécialités allemandes ?",
     "Ja / Nein, ich esse ...", "deutsch,spezialität,ja,nein",
     "hobby_1", "hobby_1", "", 23),

    # --- Catégorie 5 : LOISIRS ---
    ("Loisirs", "hobby_1",
     "Was machst du gern in deiner Freizeit?",
     "Que fais-tu volontiers pendant ton temps libre ?",
     "Ich ... gern", "gern,freizeit,hobby",
     "hobby_2", "hobby_2", "hobby", 24),
    ("Loisirs", "hobby_2",
     "Treibst du Sport?",
     "Fais-tu du sport ?",
     "Ja, ich spiele ... / Nein, ich mache keinen Sport", "sport,spiele,ja,nein",
     "hobby_3", "hobby_3", "sport", 25),
    ("Loisirs", "hobby_3",
     "Hörst du gern Musik?",
     "Aimes-tu écouter de la musique ?",
     "Ja, ich höre gern ...", "musik,höre,ja,nein",
     "hobby_4", "hobby_4", "music", 26),
    ("Loisirs", "hobby_4",
     "Siehst du gern Filme?",
     "Aimes-tu regarder des films ?",
     "Ja, ich sehe gern ... / Nein", "filme,sehe,ja,nein",
     "hobby_5", "hobby_5", "movies", 27),
    ("Loisirs", "hobby_5",
     "Liest du gern Bücher?",
     "Aimes-tu lire des livres ?",
     "Ja, ich lese gern ...", "bücher,lese,ja,nein",
     "travel_1", "travel_1", "books", 28),

    # --- Catégorie 6 : VOYAGE ---
    ("Voyage", "travel_1",
     "Reist du gern? Wohin bist du letztes Jahr gefahren?",
     "Aimes-tu voyager ? Où es-tu allé(e) l'année dernière ?",
     "Ich bin nach ... gefahren", "reise,gefahren,nach",
     "travel_2", "travel_2", "last_trip", 29),
    ("Voyage", "travel_2",
     "Schön! Wie bist du dorthin gereist? Mit dem Auto oder mit dem Zug?",
     "Bien ! Comment as-tu voyagé là-bas ? En voiture ou en train ?",
     "Ich bin mit ... gereist", "auto,zug,flugzeug,gereist",
     "travel_3", "travel_3", "transport", 30),
    ("Voyage", "travel_3",
     "Wie lange warst du dort?",
     "Combien de temps y es-tu resté(e) ?",
     "Ich war ... Tage / Wochen dort", "tage,wochen,dort,war",
     "travel_4", "travel_4", "trip_duration", 31),
    ("Voyage", "travel_4",
     "War es schön? Was hast du dort gemacht?",
     "C'était beau ? Qu'as-tu fait là-bas ?",
     "Ich habe ... gemacht", "gemacht,schön,war",
     "travel_5", "travel_5", "trip_activity", 32),
    ("Voyage", "travel_5",
     "Möchtest du nächstes Jahr wieder reisen?",
     "Veux-tu voyager à nouveau l'année prochaine ?",
     "Ja, ich möchte nach ... reisen", "reisen,möchte,nächstes",
     "work_1", "work_1", "", 33),

    # --- Catégorie 7 : TRAVAIL / ÉTUDES ---
    ("Travail", "work_1",
     "Was machst du beruflich? Arbeitest du oder studierst du?",
     "Que fais-tu comme métier ? Travailles-tu ou étudies-tu ?",
     "Ich arbeite als ... / Ich studiere ...", "arbeite,studiere,beruf",
     "work_2", "work_2", "job", 34),
    ("Travail", "work_2",
     "Wie lange arbeitest du schon?",
     "Depuis combien de temps travailles-tu ?",
     "Ich arbeite seit ... Jahren", "jahre,seit,arbeite",
     "work_3", "work_3", "work_duration", 35),
    ("Travail", "work_3",
     "Gefällt dir deine Arbeit?",
     "Ton travail te plaît-il ?",
     "Ja, sehr / Nein, nicht so", "gefällt,arbeit,ja,nein",
     "work_4", "work_4", "likes_job", 36),
    ("Travail", "work_4",
     "Wann beginnt deine Arbeit oder dein Unterricht?",
     "Quand commence ton travail ou tes cours ?",
     "Um ... Uhr", "uhr,beginnt",
     "work_5", "work_5", "work_start", 37),
    ("Travail", "work_5",
     "Warum lernst du Deutsch?",
     "Pourquoi apprends-tu l'allemand ?",
     "Ich lerne Deutsch, weil ...", "deutsch,weil,lerne",
     "weather_1", "weather_1", "why_german", 38),

    # --- Catégorie 8 : MÉTÉO ---
    ("Météo", "weather_1",
     "Wie ist das Wetter heute bei dir?",
     "Quel temps fait-il aujourd'hui chez toi ?",
     "Es ist ... / Es regnet / Es schneit", "wetter,regnet,schneit,ist",
     "weather_2", "weather_2", "weather_today", 39),
    ("Météo", "weather_2",
     "Welche Jahreszeit magst du am liebsten?",
     "Quelle saison préfères-tu ?",
     "Ich mag ... am liebsten", "jahreszeit,sommer,winter,mag",
     "weather_3", "weather_3", "fav_season", 40),
    ("Météo", "weather_3",
     "Warum magst du diese Jahreszeit?",
     "Pourquoi aimes-tu cette saison ?",
     "Weil ...", "weil,jahreszeit",
     "objects_1", "objects_1", "", 41),

    # --- Catégorie 9 : OBJETS ---
    ("Objets", "objects_1",
     "Ich zeige dir ein Bild. Was ist das? (Ein Handy) Antworte: Das ist ein ...",
     "Je te montre une image. Qu'est-ce que c'est ? (Un téléphone) Réponds : C'est un ...",
     "Das ist ein Handy", "handy,telefon,das",
     "objects_2", "objects_2", "", 42),
    ("Objets", "objects_2",
     "Richtig! Wofür benutzt du dein Handy?",
     "Correct ! À quoi utilises-tu ton téléphone ?",
     "Ich benutze mein Handy für ...", "benutze,handy,für",
     "objects_3", "objects_3", "phone_use", 43),
    ("Objets", "objects_3",
     "Was ist das? (Ein Buch) Antworte: Das ist ein ...",
     "Qu'est-ce que c'est ? (Un livre) Réponds : C'est un ...",
     "Das ist ein Buch", "buch,das,ein",
     "objects_4", "objects_4", "", 44),
    ("Objets", "objects_4",
     "Richtig! Liest du gern Bücher?",
     "Correct ! Aimes-tu lire des livres ?",
     "Ja, ich lese gern / Nein", "lese,bücher,ja,nein",
     "free_1", "free_1", "", 45),

    # --- Catégorie 10 : MODE LIBRE (fallbacks) ---
    ("Libre", "free_1",
     "Möchtest du über etwas Bestimmtes sprechen? Wähle ein Thema: Familie, Essen, Hobbys oder Reisen?",
     "Veux-tu parler de quelque chose en particulier ? Choisis un thème : famille, nourriture, loisirs ou voyage ?",
     "Familie / Essen / Hobbys / Reisen", "familie,essen,hobbys,reisen",
     "family_1", "food_1", "", 46),
    ("Libre", "free_2",
     "Erzähl mir mehr! Was hast du gestern gemacht?",
     "Raconte-moi plus ! Qu'as-tu fait hier ?",
     "Ich habe ... gemacht", "gestern,gemacht,habe",
     "free_3", "free_3", "yesterday", 47),
    ("Libre", "free_3",
     "Interessant! Und was machst du morgen?",
     "Intéressant ! Et que fais-tu demain ?",
     "Morgen ...", "morgen,mache",
     "free_4", "free_4", "tomorrow", 48),
    ("Libre", "free_4",
     "Sehr schön! Jetzt bist du dran: Stelle mir eine Frage!",
     "Très bien ! Maintenant à toi : pose-moi une question !",
     "Wie heißt du? / Wo wohnst du?", "frage,wie,wo",
     "present_finish", "present_finish", "", 49),
]

def seed_neferti_scenarios(cursor):
    for (category, step_key, de, fr, expected, keywords,
         f_yes, f_no, mem_key, order_i) in NEFERTI_SCENARIOS:
        cursor.execute(
            """INSERT INTO neferti_scenarios
            (category, step_key, neferti_de, neferti_fr, expected_de, keywords,
             followup_yes, followup_no, memory_key, order_index)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(step_key) DO UPDATE SET category=excluded.category, neferti_de=excluded.neferti_de,
              neferti_fr=excluded.neferti_fr, expected_de=excluded.expected_de, keywords=excluded.keywords,
              followup_yes=excluded.followup_yes, followup_no=excluded.followup_no,
              memory_key=excluded.memory_key, order_index=excluded.order_index""",
            (category, step_key, de, fr, expected, keywords,
             f_yes, f_no, mem_key, order_i)
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
# SÉCURITÉ v4.1 : limite de connexions, CSRF, rendu des pages
# ---------------------------------------------------------
LOGIN_MAX_FAILS = 8          # échecs max par (IP + email) sur la fenêtre
LOGIN_MAX_FAILS_MAIL = 30    # échecs max par email (toutes IP) sur la fenêtre
LOGIN_WINDOW = 900           # secondes (15 min)

def _client_ip():
    xf = request.headers.get("X-Forwarded-For", "")
    ip = xf.split(",")[-1].strip() if xf else (request.remote_addr or "")
    return ip or "?"

def _login_keys(ident):
    ident = (ident or "").strip().lower()
    k_ip = "ip|" + hashlib.sha1((_client_ip() + "|" + ident).encode("utf-8")).hexdigest()
    k_id = "id|" + hashlib.sha1(ident.encode("utf-8")).hexdigest()
    return k_ip, k_id

def _login_blocked(db, k_ip, k_id):
    db.execute("DELETE FROM login_attempts WHERE ts < ?", (time.time() - LOGIN_WINDOW,))
    n_ip = db.execute("SELECT COUNT(*) FROM login_attempts WHERE k=?", (k_ip,)).fetchone()[0]
    n_id = db.execute("SELECT COUNT(*) FROM login_attempts WHERE k=?", (k_id,)).fetchone()[0]
    return n_ip >= LOGIN_MAX_FAILS or n_id >= LOGIN_MAX_FAILS_MAIL

def _login_fail(db, k_ip, k_id):
    now = time.time()
    db.execute("INSERT INTO login_attempts(k, ts) VALUES(?,?)", (k_ip, now))
    db.execute("INSERT INTO login_attempts(k, ts) VALUES(?,?)", (k_id, now))
    db.commit()

def _login_ok(db, k_ip):
    db.execute("DELETE FROM login_attempts WHERE k=?", (k_ip,))
    db.commit()

def csrf_token():
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_hex(16)
        session["_csrf"] = tok
    return tok

_FORM_POST_RE = re.compile(r'(<form\b[^>]*\bmethod\s*=\s*["\']post["\'][^>]*>)', re.I)

def page(html):
    """Renvoie la page TELLE QUELLE (jamais interprétée par Jinja : plus d'injection de
    template) et ajoute le jeton CSRF dans chaque formulaire POST."""
    hidden = '<input type="hidden" name="csrf_token" value="%s">' % csrf_token()
    return _FORM_POST_RE.sub(lambda m: m.group(1) + hidden, html)

@app.before_request
def _csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    good = session.get("_csrf", "")
    if good and sent and hmac.compare_digest(str(sent), str(good)):
        return None
    if request.is_json or request.path.startswith("/neferti/"):
        return jsonify({"error": "Session expirée. Recharge la page."}), 400
    flash("Session expirée, réessaie.", "warning")
    ref = request.referrer or ""
    if ref and urlparse(ref).netloc == request.host:
        return redirect(ref)
    return redirect(url_for("index"))

@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp

# ---------------------------------------------------------
# DONNÉES DE PLAYLISTS (partagées par /playlists et les pages de contenu)
# ---------------------------------------------------------
def _json_for_script(obj):
    return (json.dumps(obj, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))

def playlist_data_script(payload):
    """Fusionne des playlists dans window.NATHO_PLAYLISTS (sans écraser les autres)."""
    return ("<script>(function(){var n=" + _json_for_script(payload) + ";"
            "var d=window.NATHO_PLAYLISTS=window.NATHO_PLAYLISTS||{};"
            "Object.keys(n).forEach(function(k){"
            "if(k==='order'){d.order=Object.assign(d.order||{},n.order);}else{d[k]=n[k];}"
            "});})();</script>")

def _speak_playlists(db):
    return {r["title"]: json.loads(r["items_json"]) for r in db.execute(
        "SELECT title, items_json FROM speak_playlists WHERE kind='speak' ORDER BY id").fetchall()}

def _essentials_playlists(db):
    return {r["title"]: json.loads(r["items_json"]) for r in db.execute(
        "SELECT title, items_json FROM speak_playlists WHERE kind='essentials' ORDER BY id").fetchall()}

def _nomakk_playlists(db):
    return {r["title"]: json.loads(r["items_json"]) for r in db.execute(
        "SELECT title, items_json FROM nomakk_playlist ORDER BY id").fetchall()}

def _dialogue_playlists(db):
    rows = db.execute("SELECT title, lines_json FROM dialogues ORDER BY id").fetchall()
    data = {}
    for r in rows:
        data[r["title"]] = [{"fr": l["fr"], "de": l["de"]} for l in json.loads(r["lines_json"])]
    return data, [r["title"] for r in rows]

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

# =========================================================
# === NEFERTI : logique de comparaison (Levenshtein) ===
# =========================================================
def _levenshtein(a, b):
    a = a.lower().strip()
    b = b.lower().strip()
    if a == b: return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                          prev[j - 1] + (0 if ca == cb else 1)))
        prev = cur
    return prev[-1]

def _norm_text(s):
    s = (s or "").lower()
    s = re.sub(r"[^\w\säöüß]", " ", s)
    return re.sub(r"\s+", " ", s).strip()

def _lev_ratio(a, b):
    m = max(len(a), len(b), 1)
    return max(0.0, 1.0 - _levenshtein(a, b) / m)

def _best_window(part, heard):
    """Meilleure ressemblance (0..1) entre `part` et une portion de `heard`."""
    pw = part.split()
    hw = heard.split()
    if not pw or not hw:
        return 0.0
    n = len(pw)
    best = 0.0
    for size in {max(1, n - 1), n, n + 1}:
        for i in range(0, max(1, len(hw) - size + 1)):
            best = max(best, _lev_ratio(part, " ".join(hw[i:i + size])))
    return best

def _score_pronunciation(expected, heard):
    """Score 0-100. `expected` peut contenir des « ... » (parties personnelles, ignorées) et
    plusieurs variantes séparées par « / » : on garde la meilleure variante."""
    hd = _norm_text(heard)
    if not hd:
        return 0
    best = 0.0
    for variant in str(expected or "").split("/"):
        parts = [_norm_text(p) for p in variant.split("...")]
        parts = [p for p in parts if p]
        if not parts:
            continue
        if "..." in variant:
            s = sum(_best_window(p, hd) for p in parts) / len(parts)
        else:
            vv = _norm_text(variant)
            s = max(_lev_ratio(vv, hd), _best_window(vv, hd))
        best = max(best, s)
    return int(round(best * 100))

def _keyword_hit(keywords_csv, heard):
    toks = set(_norm_text(heard).split())
    return any(k.strip().lower() in toks for k in (keywords_csv or "").split(",") if k.strip())

def _build_correction(expected, heard, score):
    """Retourne une correction en français."""
    if score >= 85:
        return ""
    if score >= 60:
        return f"Presque ! Neferti a entendu « {heard} ». Modèle de phrase : « {expected} »."
    return (f"Ce n'est pas tout à fait ça. Neferti a entendu « {heard} », "
            f"mais le modèle attendu était « {expected} ». Réessaie en articulant bien.")

def _save_memory(user_id, key, value):
    if not key or not value:
        return
    db = get_db()
    db.execute(
        """INSERT INTO neferti_memory(user_id, mem_key, mem_value)
           VALUES(?,?,?)
           ON CONFLICT(user_id, mem_key) DO UPDATE SET
           mem_value=excluded.mem_value, updated_at=CURRENT_TIMESTAMP""",
        (user_id, key, value.strip()[:120])
    )
    db.commit()

def _get_memory(user_id):
    db = get_db()
    rows = db.execute(
        "SELECT mem_key, mem_value FROM neferti_memory WHERE user_id=?",
        (user_id,)
    ).fetchall()
    return {r["mem_key"]: r["mem_value"] for r in rows}

def _save_history(user_id, role, fr_text="", de_text="", heard_text="", score=0):
    db = get_db()
    db.execute(
        "INSERT INTO neferti_history(user_id, role, fr_text, de_text, heard_text, score) "
        "VALUES(?,?,?,?,?,?)",
        (user_id, role, fr_text[:400], de_text[:400], heard_text[:400], score)
    )
    db.commit()

def _get_scenario(step_key):
    db = get_db()
    return db.execute(
        "SELECT * FROM neferti_scenarios WHERE step_key=? LIMIT 1",
        (step_key,)
    ).fetchone()

def _scenario_exists(step_key):
    return _get_scenario(step_key) is not None

# ---------------------------------------------------------
# CSS & JS
# ---------------------------------------------------------
FAVICON_SVG = """data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%2387CEEB'/><path d='M30 65V45c0-15 10-25 20-25s20 10 20 25v20' stroke='white' stroke-width='8' fill='none' stroke-linecap='round'/><rect x='25' y='60' width='12' height='20' rx='4' fill='white'/><rect x='63' y='60' width='12' height='20' rx='4' fill='white'/><text x='50' y='58' font-family='Arial' font-size='28' font-weight='bold' fill='white' text-anchor='middle'>N</text></svg>"""

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

#voice-toast {
  position: fixed; left: 50%; bottom: 90px; transform: translateX(-50%) translateY(20px);
  background: #A02A1B; color: white; padding: 12px 18px; border-radius: 10px;
  font-size: 14px; font-weight: 500; max-width: 90%; text-align: center;
  opacity: 0; pointer-events: none; transition: .25s; z-index: 200;
}
#voice-toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

.pwd-wrapper { position: relative; }
.pwd-wrapper input { padding-right: 40px; }
.pwd-toggle { position: absolute; right: 12px; top: 14px; cursor: pointer; font-size: 18px; color: var(--muted); }
.pwd-toggle:hover { color: var(--ink); }

.fiche { background: var(--card-bg); border-radius: 14px; padding: 18px; margin-bottom: 14px; border-left: 5px solid var(--sky); }
.fiche h3 { color: var(--sky-dark); font-size: 16px; margin-bottom: 10px; }
.fiche .content { font-family: 'Courier New', monospace; background: var(--input-bg); padding: 12px; border-radius: 8px; font-size: 13px; white-space: pre-wrap; line-height: 1.6; color: var(--ink); }
.fiche .explanation { margin-top: 10px; font-size: 13px; color: var(--muted); font-style: italic; padding: 10px; background: rgba(135,206,235,0.12); border-radius: 8px; }

.nomakk-section { background: var(--card-bg); border-radius: 14px; padding: 18px; margin-bottom: 14px; border-left: 5px solid var(--warn); }
.nomakk-section h3 { color: var(--warn); font-size: 16px; margin-bottom: 10px; }
.nomakk-section .content { background: var(--input-bg); padding: 14px; border-radius: 8px; font-size: 13px; white-space: pre-wrap; line-height: 1.7; color: var(--ink); font-family: 'Segoe UI', sans-serif; }
.nomakk-section .explanation { margin-top: 10px; font-size: 13px; color: var(--ink); font-style: italic; padding: 10px; background: rgba(243,156,18,0.12); border-radius: 8px; border-left: 3px solid var(--warn); }

/* === NEFERTI : chat vocal === */
.neferti-header {
  background: linear-gradient(135deg, #FF9BC7, #FF6FA5);
  color: white; border-radius: 18px; padding: 22px; margin-bottom: 18px;
  display: flex; align-items: center; gap: 16px;
}
.neferti-avatar {
  width: 70px; height: 70px; border-radius: 50%;
  background: white; display: flex; align-items: center; justify-content: center;
  font-size: 36px; flex-shrink: 0;
  box-shadow: 0 0 0 4px rgba(255,255,255,0.3);
}
.neferti-avatar.listening { animation: pulse 1s infinite; }
@keyframes pulse {
  0%,100% { box-shadow: 0 0 0 4px rgba(255,255,255,0.3); }
  50%     { box-shadow: 0 0 0 12px rgba(255,255,255,0.15); }
}
.neferti-header h2 { color: white; margin: 0; }
.neferti-header p  { opacity: 0.95; margin: 4px 0 0; font-size: 14px; }
#neferti-chat {
  background: var(--card-bg); border-radius: 16px; padding: 18px;
  min-height: 320px; max-height: 60vh; overflow-y: auto;
  margin-bottom: 16px; box-shadow: 0 4px 14px rgba(255,111,165,.15);
  display: flex; flex-direction: column; gap: 12px;
}
.msg {
  padding: 12px 16px; border-radius: 14px; max-width: 85%;
  font-size: 14px; line-height: 1.5; animation: fadeIn 0.25s ease;
}
@keyframes fadeIn { from { opacity: 0; transform: translateY(6px);} to {opacity:1; transform:none;} }
.msg.neferti { background: #FFE4EE; color: #5A1B33; align-self: flex-start; border-bottom-left-radius: 4px; }
.msg.user    { background: #D4F5E3; color: #1E7A45; align-self: flex-end;   border-bottom-right-radius: 4px; }
html[data-theme="dark"] .msg.neferti { background: #4a2030; color: #FFD6E4; }
html[data-theme="dark"] .msg.user    { background: #1e4a35; color: #D4F5E3; }
.msg .de { font-weight: 700; margin-bottom: 4px; }
.msg .fr { opacity: 0.85; font-size: 13px; }
.msg .meta { font-size: 11px; color: var(--muted); margin-top: 6px; }
.msg .score-ok   { color: #1E7A45; font-weight: 700; }
.msg .score-mid  { color: #8A5C00; font-weight: 700; }
.msg .score-bad  { color: #A02A1B; font-weight: 700; }
.neferti-controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; justify-content: center; }
.mic-btn {
  background: linear-gradient(135deg, #FF6FA5, #FF9BC7);
  color: white; border: none; border-radius: 50%;
  width: 74px; height: 74px; font-size: 30px; cursor: pointer;
  box-shadow: 0 4px 14px rgba(255,111,165,.4); transition: .2s;
}
.mic-btn:hover { transform: scale(1.05); }
.mic-btn.listening {
  background: linear-gradient(135deg, #E74C3C, #FF6B5B);
  animation: micPulse 1s infinite;
}
@keyframes micPulse {
  0%,100% { box-shadow: 0 0 0 0 rgba(231,76,60,0.5); }
  50%     { box-shadow: 0 0 0 18px rgba(231,76,60,0); }
}
.neferti-status {
  text-align: center; font-size: 13px; color: var(--muted); margin: 8px 0;
  min-height: 20px;
}
.neferti-inputs { display: flex; gap: 10px; margin-top: 12px; }
.neferti-inputs input { flex: 1; margin: 0; }

/* === v4.1 : menu déroulant, tiroir mobile, Sprechen, compte === */
.nav-links { display: inline-flex; align-items: center; flex-wrap: wrap; }
.nav-dd { position: relative; display: inline-block; margin-left: 16px; }
.nav-dd summary { cursor: pointer; list-style: none; font-weight: 500; opacity: .95; color: white; }
.nav-dd summary::-webkit-details-marker { display: none; }
.nav-dd summary:hover { opacity: 1; text-decoration: underline; }
.nav-dd-menu {
  position: absolute; top: 140%; left: 0; z-index: 90; min-width: 170px;
  background: var(--nav-bg); border-radius: 10px; padding: 8px 6px;
  box-shadow: 0 8px 24px rgba(0,0,0,.25); display: flex; flex-direction: column;
}
.nav-dd-menu a { margin: 0; padding: 8px 12px; border-radius: 8px; white-space: nowrap; }
.nav-dd-menu a:hover { background: rgba(255,255,255,.15); text-decoration: none; }
.mobile-drawer { overflow-y: auto; }
.drawer-links a {
  display: block; color: white; text-decoration: none; padding: 11px 6px;
  border-bottom: 1px solid rgba(255,255,255,.12); font-size: 15px;
}
.drawer-links a:hover { background: rgba(255,255,255,.08); }
@media (max-width: 800px) {
  .nav-links.member { display: none; }
}
.sp-box { background: var(--sky-light); padding: 16px; border-radius: 10px; margin: 14px 0; }
.sp-actions { display: flex; flex-direction: column; align-items: center; gap: 6px; margin: 14px 0; }
.res-score { font-size: 28px; font-weight: 800; }
.res-ok { color: #1E7A45; }
.res-mid { color: #8A5C00; }
.res-bad { color: #A02A1B; }
.danger-zone { border-left: 5px solid var(--danger); }
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
    dialogues: 'Tous les dialogues'
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
      var newS = doc.getElementById('side-wrap');
      var oldS = document.getElementById('side-wrap');
      if (newS && oldS) oldS.innerHTML = newS.innerHTML;
      if (doc.body) document.body.className = doc.body.className;
      oldC.innerHTML = newC.innerHTML;
      if (window.syncThemeButtons) window.syncThemeButtons();
      if (window.closeMobileMenu) window.closeMobileMenu();
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

# === NEFERTI : voix féminine DE (pitch 1.15) + reconnaissance vocale ===
NEFERTI_JS = r"""
(function(){
  'use strict';

  var synth = window.speechSynthesis;
  var voices = [];
  var selectedVoice = null;
  var NEFERTI_PITCH = 1.15;
  var NEFERTI_RATE = 0.85;

  function refreshVoices() {
    if (!synth) return;
    voices = synth.getVoices() || [];
    var de = voices.filter(function(v){ return (v.lang||'').toLowerCase().indexOf('de') === 0; });
    var females = de.filter(function(v){ return /female|frau|anna|maja|zira|helena|katja/i.test(v.name); });
    var pick = females[0] ||
               de.find(function(v){ return /google/i.test(v.name); }) ||
               de.find(function(v){ return /natural|neural/i.test(v.name); }) ||
               de[0] || null;
    selectedVoice = pick;
  }
  if (synth) {
    refreshVoices();
    if (synth.addEventListener) synth.addEventListener('voiceschanged', refreshVoices);
    else synth.onvoiceschanged = refreshVoices;
  }

  window.NefertiSay = function(text) {
    if (!synth || !text) return;
    try { if (window.NathoAudio && window.NathoAudio.stopPlaylist) window.NathoAudio.stopPlaylist(); } catch(e){}
    try { synth.cancel(); } catch(e){}
    var u = new SpeechSynthesisUtterance(text);
    if (selectedVoice) { u.voice = selectedVoice; u.lang = selectedVoice.lang; }
    else u.lang = 'de-DE';
    u.pitch = NEFERTI_PITCH;
    u.rate = NEFERTI_RATE;
    u.volume = 1;
    synth.speak(u);
  };

  // Reconnaissance vocale (allemand)
  var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  var recognition = null;
  var isListening = false;

  window.NefertiSupported = !!SR;

  window.NefertiStartListening = function(onResult, onEnd) {
    if (!SR) { alert("La reconnaissance vocale n'est pas supportée sur ce navigateur. Utilise Chrome ou Edge."); return; }
    if (isListening) return;
    recognition = new SR();
    recognition.lang = 'de-DE';
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.maxAlternatives = 3;

    recognition.onresult = function(ev) {
      var best = '';
      for (var i = 0; i < ev.results.length; i++) {
        if (ev.results[i][0] && ev.results[i][0].transcript) {
          best = ev.results[i][0].transcript;
          break;
        }
      }
      if (onResult) onResult(best);
    };
    recognition.onerror = function(ev) {
      console.warn('STT error:', ev.error);
      if (onEnd) onEnd(ev.error);
    };
    recognition.onend = function() {
      isListening = false;
      if (onEnd) onEnd(null);
    };
    try {
      recognition.start();
      isListening = true;
    } catch(e) {
      console.warn(e);
      isListening = false;
    }
  };

  window.NefertiStopListening = function() {
    if (recognition && isListening) {
      try { recognition.stop(); } catch(e){}
      isListening = false;
    }
  };
})();
"""

THEME_MOBILE_JS = r"""
<script>
(function(){
  window.syncThemeButtons = function(){
    var t = document.documentElement.getAttribute('data-theme') || 'light';
    document.querySelectorAll('.theme-toggle').forEach(function(b){ b.textContent = t === 'dark' ? '☀️' : '🌙'; });
  };
  function applyTheme(t){
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('natho_theme', t); } catch(e){}
    window.syncThemeButtons();
  }
  window.toggleTheme = function(){
    var cur = document.documentElement.getAttribute('data-theme') || 'light';
    applyTheme(cur === 'dark' ? 'light' : 'dark');
  };
  var saved = null;
  try { saved = localStorage.getItem('natho_theme'); } catch(e){}
  applyTheme(saved === 'dark' ? 'dark' : 'light');

  window.openMobileMenu = function(){
    var d = document.getElementById('mobile-drawer');
    if (d) d.classList.add('open');
  };
  window.closeMobileMenu = function(){
    var d = document.getElementById('mobile-drawer');
    if (d) d.classList.remove('open');
  };
  document.addEventListener('click', function(e){
    document.querySelectorAll('.nav-dd[open]').forEach(function(d){
      if (!d.contains(e.target)) d.removeAttribute('open');
    });
  });
})();
</script>
"""

def layout(title, body, user=None):
    show_sidebar = bool(user)

    nav_links = ""
    drawer_links = ""
    if user:
        admin_link = f"<a href='{url_for('admin')}'>Admin</a>" if user['is_admin'] else ""
        nav_links = f"""<span class="nav-links member">
            <a href="{url_for('dashboard')}">Cours</a>
            <a href="{url_for('vocabulaire')}">Vocabulaire 📖</a>
            <a href="{url_for('dialogues')}">Dialogues 🗣️</a>
            <a href="{url_for('playlists')}">Playlists 🎵</a>
            <details class="nav-dd"><summary>Apprendre ▾</summary><div class="nav-dd-menu">
              <a href="{url_for('apprendre_parler')}">Parler 🗨️</a>
              <a href="{url_for('essentiels_a1')}">Essentiels A1</a>
              <a href="{url_for('nom_akk')}">NOM/AKK</a>
            </div></details>
            <a href="{url_for('neferti')}">Neferti 🤖</a>
            <a href="{url_for('goethe')}">Examen Goethe</a>
            <details class="nav-dd"><summary>Mon espace ▾</summary><div class="nav-dd-menu">
              <a href="{url_for('progress')}">Progrès</a>
              <a href="{url_for('compte')}">Mon compte</a>
            </div></details>
            {admin_link}
            <a href="{url_for('logout')}">Déconnexion</a>
        </span>"""
        drawer_links = f"""<div class="drawer-links">
            <a href="{url_for('dashboard')}">Cours</a>
            <a href="{url_for('vocabulaire')}">Vocabulaire 📖</a>
            <a href="{url_for('dialogues')}">Dialogues 🗣️</a>
            <a href="{url_for('playlists')}">Playlists 🎵</a>
            <a href="{url_for('apprendre_parler')}">Parler 🗨️</a>
            <a href="{url_for('essentiels_a1')}">Essentiels A1</a>
            <a href="{url_for('nom_akk')}">NOM/AKK</a>
            <a href="{url_for('neferti')}">Neferti 🤖</a>
            <a href="{url_for('goethe')}">Examen Goethe</a>
            <a href="{url_for('progress')}">Progrès</a>
            <a href="{url_for('compte')}">Mon compte</a>
            {admin_link}
            <a href="{url_for('logout')}">Déconnexion</a>
        </div>"""
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

    theme_btn = '<button class="theme-toggle" onclick="toggleTheme()" title="Mode nuit">🌙</button>'
    mobile_btn = '<button class="mobile-menu-btn" onclick="openMobileMenu()" title="Menu">☰</button>' if show_sidebar else ''

    mobile_drawer = ""
    if show_sidebar:
        mobile_drawer = f"""
        <div class="mobile-drawer" id="mobile-drawer">
            <button class="close-x" onclick="closeMobileMenu()">×</button>
            <h3>Menu</h3>
            {drawer_links}
            <h3 style="margin-top:18px;">Niveaux</h3>
            <div class="level active"><strong>A1</strong> <span style="font-size:11px;display:block;">Actuel</span></div>
            <div class="level"><strong>A2</strong> <span class="tag">Bientôt</span><span style="font-size:11px;display:block;margin-top:4px;">Élémentaire</span></div>
            <div class="level"><strong>B1</strong> <span class="tag">Bientôt</span><span style="font-size:11px;display:block;margin-top:4px;">Intermédiaire</span></div>
            <div class="level"><strong>B2</strong> <span class="tag">Bientôt</span><span style="font-size:11px;display:block;margin-top:4px;">Avancé</span></div>
        </div>
        """

    flashes = ''.join(f'<div class="flash {h(str(k))}">{h(str(m))}</div>'
                      for k, m in get_flashed_messages(with_categories=True))

    return f"""
<!doctype html><html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NATHO — {h(str(title))}</title>
<link rel="icon" type="image/svg+xml" href="{FAVICON_SVG}">
{BASE_CSS}
</head><body class="{body_class}">

<div id="side-wrap">
{sidebar_html}
{mobile_drawer}
</div>

<div class="nav">
  <div class="brand"><img src="{FAVICON_SVG}" width="28" height="28" style="border-radius:6px;"> NATHO · Deutsch A1</div>
  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">{nav_links} {theme_btn} {mobile_btn}</div>
</div>
<div class="container">
  {flashes}
  {body}
</div>

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
    © NATHO — Plateforme d'apprentissage de l'allemand A1 · v4.1<br>
    <a href="/politique">Politique de confidentialité</a> |
    <a href="/cgu">Conditions d'utilisation</a> |
    <a href="/mentions">Mentions légales</a>
</footer>
<script>window.NATHO_TTS = {'true' if TTS_OK else 'false'};</script>
<script>{AUDIO_JS}</script>
<script>{NEFERTI_JS}</script>
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

TTS_CACHE_MAX_BYTES = int(os.environ.get("NATHO_TTS_CACHE_MB", "300")) * 1024 * 1024
TTS_RATE_MAX = 400        # nouveaux fichiers générés max par utilisateur...
TTS_RATE_WINDOW = 600     # ...sur 10 minutes (par worker)
_tts_hits = {}

def _tts_rate_ok(uid):
    now = time.time()
    dq = _tts_hits.setdefault(uid, deque())
    while dq and dq[0] < now - TTS_RATE_WINDOW:
        dq.popleft()
    if len(dq) >= TTS_RATE_MAX:
        return False
    dq.append(now)
    return True

def _tts_purge():
    """Supprime les plus anciens MP3 quand le cache dépasse la limite (évite de remplir le disque)."""
    try:
        files = []
        for name in os.listdir(TTS_DIR):
            p = os.path.join(TTS_DIR, name)
            if name.endswith(".mp3"):
                files.append((os.path.getmtime(p), os.path.getsize(p), p))
        total = sum(f[1] for f in files)
        if total <= TTS_CACHE_MAX_BYTES:
            return
        files.sort()
        for _, size, p in files:
            if total <= TTS_CACHE_MAX_BYTES * 0.8:
                break
            try:
                os.remove(p)
                total -= size
            except OSError:
                pass
    except Exception:
        pass

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
        if not _tts_rate_ok(session.get("user_id")):
            return ("", 429)
        tmp = path + "." + secrets.token_hex(4) + ".tmp"
        try:
            try:
                tts_obj = gTTS(text=text, lang=lang, timeout=15)
            except TypeError:
                tts_obj = gTTS(text=text, lang=lang)
            tts_obj.save(tmp)
            os.replace(tmp, path)
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return ("", 502)
        if random.random() < 0.05:
            _tts_purge()
    return send_file(path, mimetype="audio/mpeg", conditional=True, max_age=604800)

# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------
@app.route("/")
def index():
    user = None
    if "user_id" in session:
        user = {"is_admin": session.get("is_admin")}
    db = get_db()
    n_lessons = db.execute("SELECT COUNT(*) FROM lessons").fetchone()[0]
    n_vocab = db.execute("SELECT COUNT(*) FROM vocab").fetchone()[0]
    n_speak = db.execute("SELECT COUNT(*) FROM speak_phrases").fetchone()[0]
    n_dialogues = db.execute("SELECT COUNT(*) FROM dialogues").fetchone()[0]
    body = f"""
    <div class="hero">
        <h1>Bienvenue sur NATHO</h1>
        <p>Apprends l'allemand A1 comme sur Spotify : écoute, répète, progresse.</p>
        <a href="/register" class="btn">Commencer gratuitement</a>
        <a href="/login" class="btn ghost" style="background:white;color:#2F8CBB">Se connecter</a>
    </div>
    <div class="grid">
        <div class="card"><h3>🎧 Mode Audio</h3><p>Le français puis l'allemand, lu à voix haute. Idéal pour mémoriser.</p></div>
        <div class="card"><h3>📚 Bibliothèque A1</h3><p>{n_lessons} expressions et {n_vocab} mots issus du programme Goethe A1.</p></div>
        <div class="card"><h3>🗣️ Dialogues</h3><p>{n_dialogues} dialogues de la vie réelle, avec playlist audio.</p></div>
        <div class="card"><h3>🗨️ Apprendre à parler</h3><p>{n_speak} phrases complètes classées par thème : Sujet + Verbe + Complément.</p></div>
        <div class="card"><h3>⚖️ NOM/AKK</h3><p>Comprendre enfin Nominatif vs Akkusativ : der/den, ein/einen, kein/keinen.</p></div>
        <div class="card"><h3>🤖 Neferti</h3><p>Ton assistante vocale pour t'entraîner au Sprechen en allemand.</p></div>
        <div class="card"><h3>📝 Examen Goethe A1</h3><p>Hören, Lesen, Schreiben, Sprechen : un vrai simulateur d'examen.</p></div>
        <div class="card"><h3>📈 Suivi personnel</h3><p>Ton compte, tes progrès, tes résultats, à tout moment.</p></div>
    </div>
    """
    return page(layout("Accueil", body, user))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        pwd = request.form.get("password","")
        
        if not name or not email or not pwd:
            flash("Tous les champs sont requis.","danger"); return redirect(url_for("register"))
        
        if len(name) > 60 or len(email) > 120:
            flash("Nom ou email trop long.","danger"); return redirect(url_for("register"))

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
    return page(layout("Inscription", body))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pwd = request.form.get("password","")
        db = get_db()
        k_ip, k_id = _login_keys(email)
        if _login_blocked(db, k_ip, k_id):
            flash("Trop de tentatives. Réessaie dans quelques minutes.","danger")
            return redirect(url_for("login"))
        row = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        if row and check_pwd(row["password"], pwd):
            _login_ok(db, k_ip)
            if _is_legacy_hash(row["password"]):
                db.execute("UPDATE users SET password=? WHERE id=?", (hash_pwd(pwd), row["id"]))
                db.commit()
            session.clear()
            session["user_id"] = row["id"]
            session["user_name"] = row["name"]
            session["is_admin"] = bool(row["is_admin"])
            flash(f"Bienvenue {row['name']} !","success")
            return redirect(url_for("admin") if row["is_admin"] else url_for("dashboard"))

        _login_fail(db, k_ip, k_id)
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
    return page(layout("Connexion", body))

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
    n_nomakk = db.execute("SELECT COUNT(*) FROM nomakk_sections").fetchone()[0]

    tabs = f'<a href="{url_for("dashboard")}" class="{"active" if not cat else ""}">Tout</a>'
    for c in cats:
        tabs += f'<a href="{url_for("dashboard", cat=c["category"])}" class="{"active" if cat==c["category"] else ""}">{h(c["category"])}</a>'

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
          <div class="cat">{h(l['category'])}</div>
          <div class="de">{h(l['german'])}</div>
          <div class="fr">{h(l['french'])}</div>
          <div class="actions">
            {say_btn("▶ Écouter", "pair", l['french'], l['german'])}
            {say_btn("🔊 Allemand", "de", l['french'], l['german'], css="btn ghost")}
            <a class="btn ghost" href="{url_for('lesson', lid=l['id'])}">📖 Ouvrir</a>
            {badge}
          </div>
        </div>"""

    intro_btn = say_btn("▶ Lire la phrase", "pair", "Prêt ? Allons-y !", "Bereit? Los geht's!", css="primary")

    nomakk_card = f"""
    <div class="card" style="display:flex;justify-content:space-between;align-items:center;border-left:5px solid var(--warn);">
      <div>
        <h3 style="margin:0">⚖️ NOM/AKK — Nominatif vs Akkusativ</h3>
        <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0;">Comprends enfin der/den, ein/einen, kein/keinen en {n_nomakk} sections claires.</p>
      </div>
      <a href="{url_for('nom_akk')}" class="btn ok">Ouvrir</a>
    </div>
    """
    neferti_card = f"""
    <div class="card" style="display:flex;justify-content:space-between;align-items:center;border-left:5px solid #FF6FA5;">
      <div>
        <h3 style="margin:0">🤖 Neferti — Coach Sprechen</h3>
        <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0;">Discute vocalement en allemand avec Neferti. Correction instantanée.</p>
      </div>
      <a href="{url_for('neferti')}" class="btn" style="background:#FF6FA5;">Ouvrir</a>
    </div>
    """

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
    {neferti_card}
    {nomakk_card}
    <div class="tabs">{tabs}</div>
    <div class="grid">{cards}</div>
    """
    return page(layout("Cours", body, {"is_admin": session.get("is_admin")}))

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
    db.execute("""INSERT INTO progress(user_id,lesson_id,listened,completed) VALUES(?,?,1,0)
                  ON CONFLICT(user_id,lesson_id) DO UPDATE SET listened=1, updated_at=CURRENT_TIMESTAMP""",
               (session["user_id"], lid))
    db.commit()
    body = f"""
    <div class="player">
      <div class="fr">{h(l['french'])}</div>
      <div class="de">{h(l['german'])}</div>
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
    return page(layout(l['german'], body, {"is_admin": session.get("is_admin")}))

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
    n_words = db.execute("SELECT COUNT(*) FROM vocab").fetchone()[0]

    tabs = f'<a href="{url_for("vocabulaire")}" class="{"active" if not cat else ""}">Tout</a>'
    for c in cats:
        tabs += f'<a href="{url_for("vocabulaire", cat=c["category"])}" class="{"active" if cat==c["category"] else ""}">{h(c["category"])}</a>'

    cards = ""
    for w in words:
        cards += f"""
        <div class="lesson">
          <div class="cat">{h(w['category'])}</div>
          <div class="de">{h(w['german'])}</div>
          <div class="fr">{h(w['french'])}</div>
          <div class="actions">
            {say_btn("▶ Écouter", "pair", w['french'], w['german'])}
            {say_btn("🔊 Allemand", "de", w['french'], w['german'], css="btn ghost")}
          </div>
        </div>"""

    body = f"""
    <h1>Bibliothèque de Vocabulaire 📖</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">{n_words} mots allemands avec leur article (der, die, das), classés par thème.</p>
    <div class="tabs">{tabs}</div>
    <div class="grid">{cards}</div>
    """
    return page(layout("Vocabulaire", body, {"is_admin": session.get("is_admin")}))

@app.route("/dialogues")
@login_required
def dialogues():
    db = get_db()
    rows = db.execute("SELECT * FROM dialogues ORDER BY id").fetchall()
    dlg_data, dlg_order = _dialogue_playlists(db)
    pl_script = playlist_data_script({"dialogues": dlg_data, "order": {"dialogues": dlg_order}})

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
                <div style="font-size:16px; font-weight:bold; color:#0F2A3F;">{h(l['de'])}</div>
                <div style="font-size:13px; color:#5B7A90;">{h(l['fr'])}</div>
            </div>
            """

        cards += f"""
        <div class="card">
            <h3>{h(r['title'])}</h3>
            <div style="margin:10px 0;">
                {say_btn("▶ Écouter (FR puis DE)", "pair", fr_full, de_full, css="primary")}
                {playlist_btn("▶ Playlist (réplique par réplique)", "dialogues", r['title'], css="btn ok")}
            </div>
            <div style="max-height: 300px; overflow-y: auto; padding-right: 10px;">
                {chat_html}
            </div>
        </div>
        """

    body = f"""
    <h1>Dialogues du quotidien 🗣️</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">{len(rows)} dialogues de la vie réelle. Écoute-les en entier ou lance la playlist pour tout enchaîner.</p>
    <div class="card" style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
        <div>
            <h3 style="margin:0">Tous les dialogues</h3>
            <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">Les {len(rows)} dialogues lus à la suite (français puis allemand).</p>
        </div>
        {playlist_btn("▶ Lire tout", "all", "dialogues", css="btn ok")}
    </div>
    {cards}
    {pl_script}
    """
    return page(layout("Dialogues", body, {"is_admin": session.get("is_admin")}))

@app.route("/apprendre-parler")
@login_required
def apprendre_parler():
    db = get_db()
    rows = db.execute(
        "SELECT theme, theme_order, fr, de FROM speak_phrases ORDER BY theme_order, id"
    ).fetchall()

    themes = {}
    for r in rows:
        themes.setdefault((r["theme_order"], r["theme"]), []).append(r)

    tabs = ""
    sections = ""
    first = True
    for (order, theme_name), items in sorted(themes.items()):
        active = "active" if first else ""
        tabs += f'<a href="#theme-{order}" class="{active}" onclick="document.querySelectorAll(\'.tabs a\').forEach(a=>a.classList.remove(\'active\'));this.classList.add(\'active\');">{h(theme_name)}</a>'
        cards = ""
        for it in items:
            cards += f"""
            <div class="lesson">
              <div class="de">{h(it['de'])}</div>
              <div class="fr">{h(it['fr'])}</div>
              <div class="actions">
                {say_btn("▶ Écouter", "pair", it['fr'], it['de'])}
                {say_btn("🔊 Allemand", "de", it['fr'], it['de'], css="btn ghost")}
              </div>
            </div>"""
        playlist = playlist_btn("▶ Playlist de ce thème", "speak", theme_name, css="btn ok")
        sections += f"""
        <div id="theme-{order}" style="margin-top:24px;">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px;">
            <h2 style="margin:0;">{h(theme_name)}</h2>
            {playlist}
          </div>
          <div class="grid">{cards}</div>
        </div>"""
        first = False

    n = len(rows)
    pl_script = playlist_data_script({"speak": _speak_playlists(db)})
    body = f"""
    <h1>Apprendre à parler 🗨️</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">
      {n} phrases complètes classées par thème, construites sur le modèle <b>Sujet + Verbe + Complément</b>.
      Chaque phrase est lue en français puis en allemand (lentement). Utilise les playlists pour tout enchaîner.
    </p>
    <div class="tabs">{tabs}</div>
    {sections}
    {pl_script}
    """
    return page(layout("Apprendre à parler", body, {"is_admin": session.get("is_admin")}))

@app.route("/essentiels-a1")
@login_required
def essentiels_a1():
    db = get_db()
    fiches = db.execute(
        "SELECT * FROM essentials_cards ORDER BY fiche_num"
    ).fetchall()

    cards_html = ""
    for f in fiches:
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

    ess_pl = _essentials_playlists(db)
    ess_key = next(iter(ess_pl), "Les essentiels A1")
    playlist_all = playlist_btn("▶ Playlist : toutes les fiches", "essentials", ess_key, css="btn ok")
    pl_script = playlist_data_script({"essentials": ess_pl})

    body = f"""
    <h1>Les essentiels A1 📌</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">
      {len(fiches)} fiches de révision condensées pour réussir l'examen Goethe A1. Chaque fiche contient l'essentiel + une explication pédagogique.
    </p>
    <div class="card" style="display:flex;justify-content:space-between;align-items:center;">
      <div>
        <h3 style="margin:0">Écouter toutes les fiches</h3>
        <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0;">Toutes les paires français → allemand lues à la suite.</p>
      </div>
      {playlist_all}
    </div>
    {cards_html}
    {pl_script}
    """
    return page(layout("Les essentiels A1", body, {"is_admin": session.get("is_admin")}))

@app.route("/nom-akk")
@login_required
def nom_akk():
    db = get_db()
    sections = db.execute(
        "SELECT * FROM nomakk_sections ORDER BY sec_num"
    ).fetchall()

    cards_html = ""
    for s in sections:
        audio_lines = ""
        for line in s["content"].split("\n"):
            line_stripped = line.strip()
            if "=" in line_stripped and "|" not in line_stripped and "→" not in line_stripped:
                parts = line_stripped.split("=", 1)
                left = parts[0].strip()
                right = parts[1].strip()
                if left and right and len(left) < 200 and len(right) < 200:
                    audio_lines += f"""
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px dashed var(--border-light);gap:8px;">
                      <div style="flex:1;font-size:13px;"><b>{h(right)}</b> <span style="color:var(--muted);">— {h(left)}</span></div>
                      {say_btn("▶", "pair", left, right, css="btn ghost", style="padding:4px 10px;font-size:12px;")}
                    </div>
                    """
        cards_html += f"""
        <div class="nomakk-section">
          <h3>Section {s['sec_num']} — {h(s['title'])}</h3>
          <div class="content">{audio_lines if audio_lines else h(s['content'])}</div>
          <div class="explanation">💡 {h(s['explanation'])}</div>
        </div>
        """

    nom_pl = _nomakk_playlists(db)
    nom_key = next(iter(nom_pl), "NOM/AKK — Nominatif vs Akkusativ")
    playlist_all = playlist_btn("▶ Playlist : tout NOM/AKK", "nomakk", nom_key, css="btn ok")
    pl_script = playlist_data_script({"nomakk": nom_pl})

    body = f"""
    <h1>NOM/AKK — Nominatif vs Akkusativ ⚖️</h1>
    <p style="margin-bottom:16px;color:#5B7A90;">
      La technique la plus simple pour comprendre der/den, ein/einen, kein/keinen.
      {len(sections)} sections progressives avec exemples et explications.
    </p>
    <div class="card" style="display:flex;justify-content:space-between;align-items:center;border-left:5px solid var(--warn);">
      <div>
        <h3 style="margin:0">Écouter tout NOM/AKK</h3>
        <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0;">Toutes les phrases d'exemple lues à la suite.</p>
      </div>
      {playlist_all}
    </div>
    {cards_html}
    {pl_script}
    """
    return page(layout("NOM/AKK", body, {"is_admin": session.get("is_admin")}))

# =========================================================
# === NEFERTI : ROUTE PRINCIPALE ===
# =========================================================
_NEFERTI_NEG = {"nein", "nicht", "kein", "keine", "keinen", "keinem", "keiner", "nie", "niemals"}
_FREE_THEMES = [("famil", "family_1"), ("ess", "food_1"), ("hobby", "hobby_1"), ("freizeit", "hobby_1"),
                ("reis", "travel_1"), ("urlaub", "travel_1"), ("arbeit", "work_1"), ("beruf", "work_1"),
                ("wetter", "weather_1"), ("tier", "animal_1")]

def _neferti_default_step(mem):
    return "present_city" if mem.get("name") else "intro_1"

@app.route("/neferti")
@login_required
def neferti():
    user_id = session["user_id"]
    db = get_db()
    mem = _get_memory(user_id)

    # Étape courante : mémorisée côté serveur (la conversation reprend où elle s'est arrêtée)
    start = _get_scenario(mem.get("__step", "")) if mem.get("__step") else None
    if not start:
        start = _get_scenario(_neferti_default_step(mem)) or _get_scenario("intro_1")

    history = db.execute(
        "SELECT * FROM neferti_history WHERE user_id=? ORDER BY id DESC LIMIT 20",
        (user_id,)
    ).fetchall()
    history = list(reversed(history))

    # Évite les doublons : la question courante est déjà en historique si on recharge la page
    if history and history[-1]["role"] == "neferti" and history[-1]["de_text"] == start["neferti_de"]:
        history = history[:-1]
    else:
        _save_history(user_id, "neferti", start["neferti_fr"], start["neferti_de"])
    _save_memory(user_id, "__step", start["step_key"])

    hist_html = ""
    for r in history:
        if r["role"] == "neferti":
            hist_html += f"""
            <div class="msg neferti">
              <div class="de">🇩🇪 {h(r['de_text'])}</div>
              <div class="fr">🇫🇷 {h(r['fr_text'])}</div>
            </div>
            """
        else:
            score = r["score"]
            cls = "score-ok" if score >= 85 else ("score-mid" if score >= 60 else "score-bad")
            meta = f'<div class="meta">Tu as dit : « {h(r["heard_text"])} » · Score : <span class="{cls}">{score}%</span></div>' if r["heard_text"] else ""
            hist_html += f"""
            <div class="msg user">
              <div class="de">🗣️ {h(r['de_text'])}</div>
              {meta}
            </div>
            """

    visible_mem = {k: v for k, v in mem.items() if not k.startswith("__")}
    if visible_mem:
        mem_html = '<div class="card" style="margin-top:14px;"><h3>🧠 Ce que Neferti sait de toi</h3><table><thead><tr><th>Info</th><th>Valeur</th></tr></thead><tbody>'
        for k, v in visible_mem.items():
            mem_html += f"<tr><td>{h(k)}</td><td><b>{h(v)}</b></td></tr>"
        mem_html += '</tbody></table></div>'
    else:
        mem_html = '<div class="card" style="margin-top:14px;"><p style="color:var(--muted);">Neferti ne te connaît pas encore. Commence à parler pour qu\'elle mémorise tes infos !</p></div>'

    body = f"""
    <div class="neferti-header">
      <div class="neferti-avatar" id="neferti-avatar">👧</div>
      <div>
        <h2>Neferti</h2>
        <p>Ton assistante vocale pour t'entraîner au Sprechen en allemand 🇩🇪</p>
      </div>
    </div>

    <div id="neferti-chat">
      {hist_html}
      <div class="msg neferti" id="neferti-current">
        <div class="de">🇩🇪 {h(start['neferti_de'])}</div>
        <div class="fr">🇫🇷 {h(start['neferti_fr'])}</div>
      </div>
    </div>

    <div class="neferti-status" id="neferti-status">Clique sur le micro 🎤 et réponds en allemand.</div>

    <div class="neferti-controls">
      <button class="mic-btn" id="mic-btn" title="Parler à Neferti">🎤</button>
    </div>

    <div class="neferti-inputs">
      <input type="text" id="neferti-text-input" placeholder="Ou tape ta réponse en allemand ici…">
      <button class="btn" onclick="nefertiSendText()">Envoyer</button>
    </div>

    <div class="card" style="margin-top:14px;">
      <button class="btn ghost" onclick="nefertiRestart()">🔄 Recommencer la conversation</button>
    </div>

    {mem_html}

    <div class="card" style="margin-top:14px;">
      <h3>💡 Comment utiliser Neferti</h3>
      <ul style="padding-left:20px;line-height:1.8;color:var(--muted);font-size:14px;">
        <li>Clique sur <b>🎤</b> puis réponds <b>en allemand</b>. Chrome ou Edge obligatoire.</li>
        <li>Neferti t'écoute, t'écrit sa réponse en 🇩🇪 + 🇫🇷, et te parle avec une voix féminine.</li>
        <li>À la fin de ta phrase, tu verras ton <b>score de prononciation</b> et une correction si besoin.</li>
        <li>Toutes tes infos (nom, ville, animal…) sont mémorisées et réutilisées.</li>
      </ul>
    </div>

    <script>
    window.NEFERTI_STEP = {_json_for_script(start['step_key'])};
    window.NEFERTI_CAT  = {_json_for_script(start['category'])};
    window.NEFERTI_CSRF = {_json_for_script(csrf_token())};

    (function(){{
      // Dire la première phrase
      if (window.NefertiSay) {{
        window.NefertiSay({_json_for_script(start['neferti_de'])});
      }}

      var micBtn = document.getElementById('mic-btn');
      var avatar = document.getElementById('neferti-avatar');
      var statusEl = document.getElementById('neferti-status');
      var chatEl = document.getElementById('neferti-chat');
      chatEl.scrollTop = chatEl.scrollHeight;

      if (!window.NefertiSupported) {{
        statusEl.textContent = "⚠️ La reconnaissance vocale n'est pas supportée sur ce navigateur. Utilise Chrome ou Edge, ou tape ta réponse en bas.";
      }}

      micBtn.addEventListener('click', function(){{
        if (!window.NefertiSupported) {{
          alert("Reconnaissance vocale non supportée. Utilise Chrome ou Edge, ou tape ta réponse en bas.");
          return;
        }}
        micBtn.classList.add('listening');
        avatar.classList.add('listening');
        statusEl.textContent = "🎙️ Neferti t'écoute… Parle en allemand !";
        window.NefertiStartListening(function(text){{
          statusEl.textContent = "✅ J'ai entendu : « " + text + " »";
          nefertiSend(text);
        }}, function(err){{
          micBtn.classList.remove('listening');
          avatar.classList.remove('listening');
          if (err && err !== 'aborted') {{
            statusEl.textContent = "⚠️ Erreur micro : " + err + ". Réessaie.";
          }} else {{
            statusEl.textContent = "Clique sur le micro 🎤 pour parler.";
          }}
        }});
      }});

      window.nefertiSendText = function(){{
        var v = document.getElementById('neferti-text-input').value.trim();
        if (!v) return;
        document.getElementById('neferti-text-input').value = '';
        nefertiSend(v);
      }};

      window.nefertiRestart = function(){{
        if (!confirm("Recommencer la conversation ? Ta mémoire sera conservée.")) return;
        fetch('/neferti/reset', {{
          method: 'POST',
          credentials: 'same-origin',
          headers: {{ 'X-CSRF-Token': window.NEFERTI_CSRF }}
        }})
          .then(function(r){{ return r.json(); }})
          .then(function(){{
            window.location.reload();
          }});
      }};

      function nefertiSend(text){{
        micBtn.classList.remove('listening');
        avatar.classList.remove('listening');
        statusEl.textContent = "⏳ Neferti réfléchit…";

        var chat = document.getElementById('neferti-chat');
        var userMsg = document.createElement('div');
        userMsg.className = 'msg user';
        userMsg.innerHTML = '<div class="de">🗣️ ' + escapeHtml(text) + '</div>';
        chat.appendChild(userMsg);
        chat.scrollTop = chat.scrollHeight;

        fetch('/neferti/answer', {{
          method: 'POST',
          credentials: 'same-origin',
          headers: {{ 'Content-Type': 'application/json', 'X-CSRF-Token': window.NEFERTI_CSRF }},
          body: JSON.stringify({{ text: text, step: window.NEFERTI_STEP }})
        }})
        .then(function(r){{ return r.json(); }})
        .then(function(data){{
          if (data.error) {{
            statusEl.textContent = "⚠️ " + data.error;
            return;
          }}
          if (typeof data.score === 'number') {{
            var cls = data.score >= 85 ? 'score-ok' : (data.score >= 60 ? 'score-mid' : 'score-bad');
            userMsg.innerHTML += '<div class="meta">Score : <span class="' + cls + '">' + data.score + '%</span>'
              + (data.correction ? '<br>💡 ' + escapeHtml(data.correction) : '')
              + '</div>';
          }}
          var bot = document.createElement('div');
          bot.className = 'msg neferti';
          bot.innerHTML = '<div class="de">🇩🇪 ' + escapeHtml(data.neferti_de) + '</div>'
                        + '<div class="fr">🇫🇷 ' + escapeHtml(data.neferti_fr) + '</div>';
          chat.appendChild(bot);
          chat.scrollTop = chat.scrollHeight;

          if (data.next_step) window.NEFERTI_STEP = data.next_step;

          if (window.NefertiSay) window.NefertiSay(data.neferti_de);

          statusEl.textContent = "Clique sur le micro 🎤 pour répondre.";
        }})
        .catch(function(err){{
          console.error(err);
          statusEl.textContent = "⚠️ Erreur réseau. Réessaie.";
        }});
      }}

      function escapeHtml(s){{
        return String(s).replace(/[&<>"']/g, function(m){{
          return {{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[m];
        }});
      }}
    }})();
    </script>
    """
    return page(layout("Neferti", body, {"is_admin": session.get("is_admin")}))

# =========================================================
# === NEFERTI : API de réponse ===
# =========================================================
@app.route("/neferti/answer", methods=["POST"])
@login_required
def neferti_answer():
    data = request.get_json(silent=True) or {}
    heard = (data.get("text") or "").strip()[:300]
    step_key = (data.get("step") or "").strip()
    user_id = session["user_id"]

    if not heard:
        return jsonify({"error": "Aucun texte reçu."}), 400

    # L'étape de référence est celle mémorisée côté serveur (évite les désynchronisations entre onglets)
    mem = _get_memory(user_id)
    current = _get_scenario(mem.get("__step", "")) if mem.get("__step") else None
    if not current:
        current = _get_scenario(step_key) or _get_scenario("intro_1")

    # 1. Score de prononciation (les « ... » du modèle sont ignorés, les variantes « / » acceptées)
    expected = current["expected_de"] or ""
    score = _score_pronunciation(expected, heard) if expected else 100
    if expected and score < 60 and _keyword_hit(current["keywords"], heard):
        score = 60   # mots-clés attendus présents : « presque »
    correction = _build_correction(expected, heard, score) if expected else ""

    # 2. Sauvegarder la réponse utilisateur
    _save_history(user_id, "user", "", heard, heard, score)

    # 3. Mémoriser les infos extraites
    mem_key = current["memory_key"] or ""
    if mem_key:
        val = heard
        for prefix in ["ich heiße ", "ich heisse ", "mein name ist ",
                       "ich bin ", "ich komme aus ", "ich wohne in ",
                       "ich habe ", "ich mag ", "ich esse gern ",
                       "ich trinke gern ", "ich spiele gern ",
                       "ich lerne ", "ich arbeite als "]:
            if val.lower().startswith(prefix):
                val = val[len(prefix):]
                break
        _save_memory(user_id, mem_key, val.strip())

    # 4. Prochaine étape (négation détectée MOT PAR MOT ; choix de thème pour free_1)
    toks = set(re.findall(r"[a-zäöüß]+", heard.lower()))
    next_step_key = current["followup_yes"] or "free_1"
    if current["step_key"] == "free_1":
        next_step_key = "free_2"
        for stem, target in _FREE_THEMES:
            if any(t.startswith(stem) for t in toks):
                next_step_key = target
                break
    elif current["followup_no"] and (toks & _NEFERTI_NEG):
        next_step_key = current["followup_no"]
    elif current["followup_yes"]:
        next_step_key = current["followup_yes"]

    if not _scenario_exists(next_step_key):
        next_step_key = "free_1"

    next_sc = _get_scenario(next_step_key)

    # 5. Sauvegarder la réponse de Neferti et la nouvelle étape
    _save_history(user_id, "neferti", next_sc["neferti_fr"], next_sc["neferti_de"])
    _save_memory(user_id, "__step", next_step_key)

    return jsonify({
        "heard": heard,
        "score": score,
        "correction": correction,
        "neferti_de": next_sc["neferti_de"],
        "neferti_fr": next_sc["neferti_fr"],
        "next_step": next_sc["step_key"],
        "next_category": next_sc["category"],
    })

@app.route("/neferti/reset", methods=["POST"])
@login_required
def neferti_reset():
    """Recommence la conversation (la mémoire des infos personnelles est conservée)."""
    user_id = session["user_id"]
    db = get_db()
    db.execute("DELETE FROM neferti_history WHERE user_id=?", (user_id,))
    db.execute("DELETE FROM neferti_memory WHERE user_id=? AND mem_key='__step'", (user_id,))
    db.commit()
    return jsonify({"ok": True})

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

    d_rows = db.execute("SELECT * FROM dialogues ORDER BY id").fetchall()
    playlist_data_dialogues = {}
    for r in d_rows:
        lines = json.loads(r["lines_json"])
        playlist_data_dialogues[r["title"]] = [{"fr": l["fr"], "de": l["de"]} for l in lines]
        
    playlist_data_speak = {}
    speak_rows = db.execute("SELECT key, title, items_json FROM speak_playlists WHERE kind='speak'").fetchall()
    for r in speak_rows:
        playlist_data_speak[r["title"]] = json.loads(r["items_json"])

    playlist_data_essentials = {}
    ess_rows = db.execute("SELECT key, title, items_json FROM speak_playlists WHERE kind='essentials'").fetchall()
    for r in ess_rows:
        playlist_data_essentials[r["title"]] = json.loads(r["items_json"])

    playlist_data_nomakk = {}
    nomakk_rows = db.execute("SELECT key, title, items_json FROM nomakk_playlist").fetchall()
    for r in nomakk_rows:
        playlist_data_nomakk[r["title"]] = json.loads(r["items_json"])

    order_l = [r["category"] for r in db.execute(
        "SELECT category FROM lessons GROUP BY category ORDER BY MIN(order_index), MIN(id)").fetchall()]
    order_v = [r["category"] for r in db.execute(
        "SELECT category FROM vocab GROUP BY category ORDER BY MIN(id)").fetchall()]
    order_d = [r["title"] for r in d_rows]

    n_lessons = sum(len(v) for v in playlist_data_lessons.values())
    n_vocab = sum(len(v) for v in playlist_data_vocab.values())
    n_dialogues = sum(len(v) for v in playlist_data_dialogues.values())

    js_payload = ({
        "lessons": playlist_data_lessons,
        "vocab": playlist_data_vocab,
        "dialogues": playlist_data_dialogues,
        "speak": playlist_data_speak,
        "essentials": playlist_data_essentials,
        "nomakk": playlist_data_nomakk,
        "order": {"lessons": order_l, "vocab": order_v, "dialogues": order_d}
    })

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
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{n_dialogues} répliques.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "dialogues", css="btn ok")}
        </div>
        <div class="card" style="display:flex; justify-content:space-between; align-items:center; background: #D4F5E3;">
            <div>
                <h3 style="margin:0">Tout NATHO (Phrases + Vocab + Dialogues)</h3>
                <p style="color:#1E7A45;font-size:14px;margin:4px 0 0 0">{n_lessons + n_vocab + n_dialogues} éléments.</p>
            </div>
            {playlist_btn("▶ Lire tout", "all", "mix", css="btn ok")}
        </div>
    """

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

    cards_nomakk = ""
    for title, items in playlist_data_nomakk.items():
        cards_nomakk += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center; border-left:5px solid var(--warn);">
            <div>
                <h3 style="margin:0">{h(title)}</h3>
                <p style="color:var(--muted);font-size:14px;margin:4px 0 0 0">{len(items)} phrases (sections + exemples).</p>
            </div>
            {playlist_btn("▶ Playlist", "nomakk", title, css="btn ok")}
        </div>
        """

    cards_lessons = ""
    for c in cats_lessons:
        cards_lessons += f"""
        <div class="card" style="display:flex; justify-content:space-between; align-items:center;">
            <div>
                <h3 style="margin:0">{h(c['category'])}</h3>
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
                <h3 style="margin:0">{h(c['category'])}</h3>
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
                <h3 style="margin:0">{h(c)}</h3>
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

    <h2 style="margin-top:30px;">⚖️ NOM/AKK</h2>
    {cards_nomakk}

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

    {playlist_data_script(js_payload)}
    """
    return page(layout("Playlists", body, {"is_admin": session.get("is_admin")}))

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
        rows_html += f"<tr><td>{h(r['category'])}</td><td><b>{h(r['german'])}</b></td><td>{h(r['french'])}</td><td>{badge}</td><td>{play_btn}</td></tr>"

    def _goethe_parse(ex):
        try:
            data = json.loads(ex["result_json"])
        except Exception:
            return "—", False, "Erreur"
        mod = str(data.get("module", "Examen"))
        ok = data.get("score", 0) >= max(1, data.get("total", 1))
        detail = data.get("detail") or ("%s%%" % data["pct"] if "pct" in data else "")
        label = ("✔ Réussi" if ok else "✘ À revoir") + (" · " + str(detail) if detail else "")
        return mod, ok, label

    g_all = db.execute("SELECT * FROM goethe_exam WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    g_html = ""
    g_stats = {}
    for n_ex, ex in enumerate(g_all):
        mod, ok, label = _goethe_parse(ex)
        st = g_stats.setdefault(mod, [0, 0])
        st[1] += 1
        st[0] += 1 if ok else 0
        if n_ex < 15:
            g_html += f"<tr><td>{h(str(ex['taken_at']))}</td><td>{h(mod)}</td><td>{h(label)}</td></tr>"

    if not g_html:
        g_html = "<tr><td colspan='3'>Aucun examen Goethe passé pour le moment.</td></tr>"
    g_stats_html = "".join(
        f'<div class="stat"><div class="num">{a}/{b}</div><div class="lbl">{h(m)} réussis</div></div>'
        for m, (a, b) in g_stats.items())
    if g_stats_html:
        g_stats_html = f'<div class="stat-grid" style="margin-bottom:14px">{g_stats_html}</div>'

    body = f"""
    <h1>Mes progrès</h1>
    <div class="card">
      <h2>Leçons</h2>
      <table><thead><tr><th>Catégorie</th><th>Allemand</th><th>Français</th><th>État</th><th>Audio</th></tr></thead>
      <tbody>{rows_html}</tbody></table>
    </div>
    <div class="card">
      <h2>Mes examens Goethe</h2>
      {g_stats_html}
      <table><thead><tr><th>Date</th><th>Module</th><th>Résultat</th></tr></thead><tbody>{g_html}</tbody></table>
    </div>
    """
    return page(layout("Progrès", body, {"is_admin": session.get("is_admin")}))

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
        <h2>2. Neferti et la mémoire</h2>
        <p>Neferti mémorise vos informations (nom, ville, animal, etc.) pour personnaliser vos conversations. Chaque compte a sa mémoire isolée et privée : aucun utilisateur ne voit les données d'un autre.</p>
        <h2>3. Sécurité</h2>
        <p>Les mots de passe ne sont jamais stockés en clair : ils sont protégés par un hachage salé. Nous vous recommandons d'utiliser un mot de passe fort et unique.</p>
        <h2>4. Vos droits</h2>
        <p>Conformément au RGPD, vous pouvez supprimer votre compte (et donc votre progression, vos résultats et la mémoire Neferti) à tout moment depuis la page « Mon compte ».</p>
    </div>
    <a href="/" class="btn ghost">← Retour à l'accueil</a>
    """
    return page(layout("Politique de confidentialité", body, user))

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
        <p>L'ensemble du contenu est la propriété exclusive de NATHO.</p>
        <h2>3. Utilisation</h2>
        <p>Vous vous engagez à ne pas partager vos identifiants de connexion.</p>
        <h2>4. Responsabilité</h2>
        <p>NATHO ne délivre pas de certificat officiel Goethe. Les examens proposés sont des simulations.</p>
    </div>
    <a href="/" class="btn ghost">← Retour à l'accueil</a>
    """
    return page(layout("CGU", body, user))

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
    </div>
    <a href="/" class="btn ghost">← Retour à l'accueil</a>
    """
    return page(layout("Mentions légales", body, user))

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
    {"q": "Écris un message à un ami pour l'inviter à dîner ce soir. (Hallo, ...)", "min_words": 8,
     "must": [["hallo", "liebe", "guten tag"], ["einlad", "komm"], ["abend", "essen", "heute"]],
     "model": "Hallo Paul, kommst du heute Abend zum Essen zu mir? Ich koche Reis und Fisch. Bis später, Anna"},
    {"q": "Écris un message pour dire que tu es malade et que tu ne peux pas venir au cours. (Hallo, ...)", "min_words": 8,
     "must": [["hallo", "liebe", "guten tag"], ["krank"], ["kurs", "unterricht", "schule", "komm"]],
     "model": "Hallo Frau Weber, ich bin heute krank. Ich kann nicht zum Kurs kommen. Bis bald, Samuel"},
    {"q": "Écris un message pour demander le prix d'un billet de train pour Munich. (Guten Tag, ...)", "min_words": 8,
     "must": [["guten tag", "hallo", "sehr geehrte"], ["fahrkarte", "ticket", "zug"], ["münchen"], ["kost", "preis"]],
     "model": "Guten Tag, was kostet eine Fahrkarte nach München? Ich möchte am Samstag fahren. Vielen Dank"},
    {"q": "Écris un message pour t'excuser d'être en retard au rendez-vous. (Entschuldigung, ...)", "min_words": 8,
     "must": [["entschuldig", "tut mir leid"], ["spät", "zu spät"], ["bus", "zug", "komm", "warte", "bin"]],
     "model": "Entschuldigung, ich komme zu spät. Der Bus hat Verspätung. Ich bin in zehn Minuten da"},
    {"q": "Écris un message pour remercier ton ami pour le cadeau. (Liebe/r ..., ...)", "min_words": 8,
     "must": [["liebe", "lieber", "hallo"], ["danke", "dank"], ["geschenk"]],
     "model": "Lieber Paul, vielen Dank für das Geschenk. Es gefällt mir sehr. Bis bald, Anna"}
]

SPRECHEN_QUESTIONS = [
    {"q": "Présente-toi : Dis ton nom, ton pays, ta ville et ta langue maternelle.", "example": "Hallo! Ich heiße Thomas. Ich komme aus Kamerun. Ich wohne in Douala. Ich lerne Deutsch.",
     "pattern": "Ich heiße ... Ich komme aus ... Ich wohne in ..."},
    {"q": "Épelle ton nom de famille lentement à voix haute.", "example": "M-A-R-T-I-N",
     "pattern": ""},
    {"q": "Dis à voix haute que tu aimes le café et que tu n'aimes pas le thé.", "example": "Ich mag Kaffee, aber ich mag keinen Tee.",
     "pattern": "Ich mag Kaffee ... ich mag keinen Tee"},
    {"q": "Dis les jours de la semaine en allemand.", "example": "Montag, Dienstag, Mittwoch, Donnerstag, Freitag, Samstag, Sonntag.",
     "pattern": "Montag Dienstag Mittwoch Donnerstag Freitag Samstag Sonntag"},
    {"q": "Commande un café et un croissant dans un restaurant à voix haute.", "example": "Ich hätte gern einen Kaffee und ein Croissant.",
     "pattern": "Ich hätte gern einen Kaffee und ein Croissant / Ich möchte einen Kaffee und ein Croissant"}
]

# +40 questions par module (contenu ajouté en v4.1)
HOREN_EXTRA = [
    {"audio": "Der Zug nach Hamburg fährt um halb acht von Gleis drei.", "q": "À quelle heure part le train ?", "opts": ["À 7h30", "À 8h30", "À 3h00"], "ans": "0"},
    {"audio": "Das Brot kostet zwei Euro fünfzig.", "q": "Combien coûte le pain ?", "opts": ["2,50 euros", "5,20 euros", "1,50 euro"], "ans": "0"},
    {"audio": "Hallo, hier ist Lisa. Ich kann heute nicht kommen, ich habe Fieber.", "q": "Pourquoi Lisa ne peut-elle pas venir ?", "opts": ["Elle a de la fièvre", "Elle a un examen", "Elle est en retard"], "ans": "0"},
    {"audio": "Morgen regnet es in München, und es ist nur zehn Grad kalt.", "q": "Quel temps fera-t-il demain à Munich ?", "opts": ["Il pleuvra", "Il fera beau et chaud", "Il neigera"], "ans": "0"},
    {"audio": "Das Konzert beginnt am Freitag um zwanzig Uhr.", "q": "Quel jour a lieu le concert ?", "opts": ["Vendredi", "Samedi", "Jeudi"], "ans": "0"},
    {"audio": "Ich esse zum Frühstück ein Brötchen mit Käse und trinke einen Tee.", "q": "Que boit la personne au petit-déjeuner ?", "opts": ["Du thé", "Du café", "Du lait"], "ans": "0"},
    {"audio": "Meine Schwester heißt Julia. Sie ist Ärztin und arbeitet im Krankenhaus.", "q": "Où travaille Julia ?", "opts": ["À l'hôpital", "À l'école", "Dans un magasin"], "ans": "0"},
    {"audio": "Entschuldigung, ich habe ein Zimmer für zwei Nächte reserviert.", "q": "Pour combien de nuits la chambre est-elle réservée ?", "opts": ["Deux", "Une", "Quatre"], "ans": "0"},
    {"audio": "Die Bank ist neben dem Supermarkt, gleich links.", "q": "Où se trouve la banque ?", "opts": ["À côté du supermarché", "En face de la gare", "Derrière l'école"], "ans": "0"},
    {"audio": "Der Bus Nummer fünf fährt zum Flughafen.", "q": "Où va le bus numéro 5 ?", "opts": ["À l'aéroport", "À la gare", "À l'hôpital"], "ans": "0"},
    {"audio": "Ich fahre am Sonntag mit meiner Familie nach Hause.", "q": "Avec qui la personne rentre-t-elle chez elle ?", "opts": ["Avec sa famille", "Avec ses collègues", "Avec un ami"], "ans": "0"},
    {"audio": "Frau Schmidt, Ihr Termin beim Zahnarzt ist am Dienstag um zehn Uhr.", "q": "Chez qui Mme Schmidt a-t-elle rendez-vous ?", "opts": ["Chez le dentiste", "Chez le coiffeur", "Chez le médecin généraliste"], "ans": "0"},
    {"audio": "Ich möchte zwei Kilo Äpfel und eine Flasche Milch, bitte.", "q": "Que veut acheter la personne ?", "opts": ["Des pommes et du lait", "Du pain et du fromage", "Des oranges et de l'eau"], "ans": "0"},
    {"audio": "Das Museum ist montags geschlossen.", "q": "Quel jour le musée est-il fermé ?", "opts": ["Le lundi", "Le dimanche", "Le mardi"], "ans": "0"},
    {"audio": "Mein Handy ist kaputt. Ich brauche ein neues.", "q": "Quel est le problème de la personne ?", "opts": ["Son téléphone est cassé", "Elle a perdu ses clés", "Son ordinateur est lent"], "ans": "0"},
    {"audio": "Tom spielt am Wochenende Fußball mit seinen Freunden.", "q": "Que fait Tom le week-end ?", "opts": ["Il joue au football", "Il va au cinéma", "Il fait du vélo"], "ans": "0"},
    {"audio": "Wir haben heute Pizza, Salat und Suppe. Was möchten Sie trinken?", "q": "Que demande le serveur ?", "opts": ["Ce que le client veut boire", "Combien de personnes sont là", "Comment le client veut payer"], "ans": "0"},
    {"audio": "Hier ist der Anrufbeantworter von Doktor Weber. Die Praxis ist von acht bis zwölf Uhr geöffnet.", "q": "Jusqu'à quelle heure le cabinet est-il ouvert ?", "opts": ["Jusqu'à 12h", "Jusqu'à 8h", "Jusqu'à 14h"], "ans": "0"},
    {"audio": "Ich bin Peter und ich komme aus Österreich. Ich spreche Deutsch und ein bisschen Englisch.", "q": "De quel pays vient Peter ?", "opts": ["D'Autriche", "D'Allemagne", "De Suisse"], "ans": "0"},
    {"audio": "Das Hotel hat ein Schwimmbad, aber kein Restaurant.", "q": "Qu'y a-t-il dans l'hôtel ?", "opts": ["Une piscine", "Un restaurant", "Un jardin"], "ans": "0"},
    {"audio": "Mein Geburtstag ist am fünften Mai.", "q": "Quelle est la date d'anniversaire de la personne ?", "opts": ["Le 5 mai", "Le 15 mai", "Le 5 mars"], "ans": "0"},
    {"audio": "Bitte nehmen Sie die zweite Straße rechts, dann sehen Sie die Post.", "q": "Que doit faire la personne pour trouver la poste ?", "opts": ["Prendre la deuxième rue à droite", "Prendre la deuxième rue à gauche", "Aller tout droit"], "ans": "0"},
    {"audio": "Papa kommt heute spät nach Hause, er arbeitet bis neun Uhr.", "q": "Jusqu'à quelle heure papa travaille-t-il ?", "opts": ["Jusqu'à 21h", "Jusqu'à 19h", "Jusqu'à 6h"], "ans": "0"},
    {"audio": "Die Kinder haben morgen keine Schule, weil Feiertag ist.", "q": "Pourquoi les enfants n'ont-ils pas école demain ?", "opts": ["C'est un jour férié", "Ils sont malades", "Les professeurs font grève"], "ans": "0"},
    {"audio": "Ich nehme den Fisch, und meine Frau nimmt das Hähnchen.", "q": "Que prend la femme ?", "opts": ["Du poulet", "Du poisson", "Un steak"], "ans": "0"},
    {"audio": "Das T-Shirt gefällt mir, aber es ist zu klein. Haben Sie es in Größe M?", "q": "Quel est le problème avec le T-shirt ?", "opts": ["Il est trop petit", "Il est trop cher", "Il est trop grand"], "ans": "0"},
    {"audio": "Mein Bruder wohnt in Köln und arbeitet bei einer Bank.", "q": "Où travaille le frère ?", "opts": ["Dans une banque", "Dans un hôpital", "Dans une école"], "ans": "0"},
    {"audio": "Achtung, liebe Fahrgäste! Der Zug nach Wien hat zwanzig Minuten Verspätung.", "q": "Quel est le problème annoncé ?", "opts": ["Le train a du retard", "Le train est annulé", "Le train est complet"], "ans": "0"},
    {"audio": "Kommst du heute Abend mit ins Kino? Der Film beginnt um acht.", "q": "Que propose la personne ?", "opts": ["Aller au cinéma", "Aller au restaurant", "Aller à la piscine"], "ans": "0"},
    {"audio": "Ich schlafe jeden Tag bis sieben Uhr und dann dusche ich.", "q": "Jusqu'à quelle heure la personne dort-elle ?", "opts": ["Jusqu'à 7h", "Jusqu'à 6h", "Jusqu'à 9h"], "ans": "0"},
    {"audio": "Das Zimmer kostet vierzig Euro pro Nacht, mit Frühstück.", "q": "Combien coûte la chambre par nuit ?", "opts": ["40 euros", "14 euros", "60 euros"], "ans": "0"},
    {"audio": "Hier ist Frau Braun. Ich komme morgen nicht zur Arbeit, mein Sohn ist krank.", "q": "Pourquoi Mme Braun ne vient-elle pas au travail ?", "opts": ["Son fils est malade", "Elle est en vacances", "Sa voiture est en panne"], "ans": "0"},
    {"audio": "Im Sommer fahren wir an das Meer, im Winter fahren wir in die Berge.", "q": "Que font-ils en hiver ?", "opts": ["Ils vont à la montagne", "Ils vont à la mer", "Ils restent à la maison"], "ans": "0"},
    {"audio": "Ich lerne Deutsch, weil ich in Deutschland arbeiten möchte.", "q": "Pourquoi la personne apprend-elle l'allemand ?", "opts": ["Pour travailler en Allemagne", "Pour voyager en vacances", "Pour parler avec sa famille"], "ans": "0"},
    {"audio": "Der Apfelkuchen ist heute im Café nur drei Euro.", "q": "Qu'est-ce qui coûte trois euros ?", "opts": ["Un gâteau aux pommes", "Une glace", "Une pizza"], "ans": "0"},
    {"audio": "Entschuldigung, ist dieser Platz frei? Ja, bitte, setzen Sie sich.", "q": "Que répond la deuxième personne ?", "opts": ["Que la place est libre", "Que la place est prise", "Qu'elle part tout de suite"], "ans": "0"},
    {"audio": "Ich bin Lehrerin. Meine Schule ist klein, und ich habe zwanzig Schüler.", "q": "Combien d'élèves a la personne ?", "opts": ["Vingt", "Douze", "Trente"], "ans": "0"},
    {"audio": "Die Bäckerei öffnet um sechs Uhr morgens.", "q": "Quand la boulangerie ouvre-t-elle ?", "opts": ["À 6h du matin", "À 6h du soir", "À 8h du matin"], "ans": "0"},
    {"audio": "Gute Nacht, Oma! Morgen besuche ich dich.", "q": "À qui la personne parle-t-elle ?", "opts": ["À sa grand-mère", "À sa mère", "À sa tante"], "ans": "0"},
    {"audio": "Mir ist kalt. Kann ich bitte das Fenster schließen?", "q": "Que demande la personne ?", "opts": ["De fermer la fenêtre", "D'ouvrir la porte", "D'allumer la lumière"], "ans": "0"}
]

LESEN_EXTRA = [
    {"text": "Liebe Eva, am Samstag mache ich eine Party. Sie beginnt um 18 Uhr. Kommst du? Viele Grüße, Jan", "q": "Quel jour a lieu la fête ?", "opts": ["Samedi", "Dimanche", "Vendredi"], "ans": "0"},
    {"text": "Sonderangebot: Äpfel, 1 Kilo nur 1,99 Euro!", "q": "Quel est le prix des pommes ?", "opts": ["1,99 euro le kilo", "1,99 euro la pièce", "9,99 euros le kilo"], "ans": "0"},
    {"text": "Praxis Dr. Müller. Sprechzeiten: Montag bis Freitag von 8 bis 12 Uhr.", "q": "Quand le cabinet est-il ouvert ?", "opts": ["Du lundi au vendredi matin", "Le samedi matin", "Tous les après-midi"], "ans": "0"},
    {"text": "Hallo Paul, ich bin im Café am Markt. Ich warte schon 20 Minuten. Wo bist du?", "q": "Que fait l'auteur du message ?", "opts": ["Il attend Paul au café", "Il est chez lui", "Il est dans le train"], "ans": "0"},
    {"text": "Zimmer zu vermieten: 2 Zimmer, Küche, Bad, 450 Euro im Monat.", "q": "Combien coûte le logement ?", "opts": ["450 euros par mois", "540 euros par mois", "450 euros par semaine"], "ans": "0"},
    {"text": "Heute gibt es im Restaurant: Suppe, Schnitzel mit Kartoffeln und Eis. Alles zusammen 9 Euro.", "q": "Que comprend le menu du jour ?", "opts": ["Soupe, escalope et glace", "Salade et poisson", "Pizza et gâteau"], "ans": "0"},
    {"text": "Liebe Frau Klein, mein Sohn ist krank und kann heute nicht in die Schule kommen. Mit freundlichen Grüßen, Anna Berger", "q": "Pourquoi le fils ne vient-il pas à l'école ?", "opts": ["Il est malade", "Il a un rendez-vous", "Il est en vacances"], "ans": "0"},
    {"text": "Das Schwimmbad ist im August täglich von 9 bis 20 Uhr geöffnet.", "q": "En quel mois ces horaires sont-ils valables ?", "opts": ["En août", "En juillet", "En juin"], "ans": "0"},
    {"text": "Wir ziehen am 1. Mai um. Die neue Adresse ist Lindenstraße 8 in Leipzig.", "q": "Que va faire cette famille le 1er mai ?", "opts": ["Elle va déménager", "Elle va partir en vacances", "Elle va acheter une voiture"], "ans": "0"},
    {"text": "Hallo Lena, danke für deine Karte aus Italien. Bei uns ist das Wetter schlecht, es regnet jeden Tag.", "q": "Quel temps fait-il chez l'auteur ?", "opts": ["Il pleut tous les jours", "Il fait beau", "Il neige"], "ans": "0"},
    {"text": "Fahrrad zu verkaufen. Fast neu, nur 120 Euro. Bitte schreiben Sie an max@mail.de.", "q": "Que vend-on ?", "opts": ["Un vélo", "Une voiture", "Une table"], "ans": "0"},
    {"text": "Die Bibliothek ist sonntags geschlossen. Am Samstag ist sie bis 14 Uhr geöffnet.", "q": "Quand la bibliothèque est-elle fermée ?", "opts": ["Le dimanche", "Le samedi", "Le lundi"], "ans": "0"},
    {"text": "Ich suche eine Wohnung in Hamburg. Ich habe einen Hund, und ich arbeite in der Stadt.", "q": "Que cherche la personne ?", "opts": ["Un appartement", "Un travail", "Un chien"], "ans": "0"},
    {"text": "Liebe Oma, ich bin gut in Wien angekommen. Das Hotel ist klein, aber sehr sauber. Bis bald! Tim", "q": "Où se trouve Tim ?", "opts": ["À Vienne", "À Berlin", "À Zurich"], "ans": "0"},
    {"text": "Der Deutschkurs findet montags und mittwochs von 18 bis 20 Uhr statt.", "q": "Quels jours a lieu le cours d'allemand ?", "opts": ["Lundi et mercredi", "Mardi et jeudi", "Lundi et vendredi"], "ans": "0"},
    {"text": "Verzeihung, ich bin leider zu spät. Mein Bus ist nicht gekommen.", "q": "Pourquoi la personne est-elle en retard ?", "opts": ["Le bus n'est pas venu", "Elle s'est réveillée tard", "Elle a perdu ses clés"], "ans": "0"},
    {"text": "Mein Hobby ist Kochen. Am Wochenende koche ich oft für meine Freunde.", "q": "Que fait la personne le week-end ?", "opts": ["Elle cuisine pour ses amis", "Elle fait du sport", "Elle va au cinéma"], "ans": "0"},
    {"text": "Achtung! Parken verboten. Hier ist die Einfahrt von der Schule.", "q": "Que signifie cette affiche ?", "opts": ["Il est interdit de se garer", "Le parking est gratuit", "C'est l'entrée du parc"], "ans": "0"},
    {"text": "Hallo Sara, kannst du mir bitte das Buch mitbringen? Ich brauche es morgen für den Kurs. Danke! Ali", "q": "Que demande Ali à Sara ?", "opts": ["D'apporter le livre", "De prêter de l'argent", "De l'appeler"], "ans": "0"},
    {"text": "Das Hemd kostet 25 Euro. Die Hose kostet 40 Euro.", "q": "Quel article est le plus cher ?", "opts": ["Le pantalon", "La chemise", "Ils ont le même prix"], "ans": "0"},
    {"text": "Wir fahren im Juli nach Spanien. Wir bleiben zwei Wochen und fliegen von Frankfurt.", "q": "Combien de temps restent-ils en Espagne ?", "opts": ["Deux semaines", "Deux jours", "Un mois"], "ans": "0"},
    {"text": "Der Zug nach Köln fährt heute von Gleis 7 und nicht von Gleis 3.", "q": "De quel quai part le train aujourd'hui ?", "opts": ["Du quai 7", "Du quai 3", "Du quai 5"], "ans": "0"},
    {"text": "Hallo Mama, ich habe Hunger. Ich gehe jetzt in die Küche und mache Nudeln.", "q": "Que va faire l'auteur ?", "opts": ["Préparer des pâtes", "Aller au restaurant", "Acheter du pain"], "ans": "0"},
    {"text": "Gesucht: Verkäuferin für Bäckerei, Montag bis Freitag, ab 6 Uhr morgens.", "q": "Quelle personne cherche-t-on ?", "opts": ["Une vendeuse", "Une cuisinière", "Une secrétaire"], "ans": "0"},
    {"text": "Lieber Karl, herzlichen Glückwunsch zum Geburtstag! Ich wünsche dir alles Gute. Deine Nina", "q": "Pourquoi Nina écrit-elle à Karl ?", "opts": ["Pour son anniversaire", "Pour son mariage", "Pour le remercier"], "ans": "0"},
    {"text": "Bitte leise sein! Hier schlafen die Kinder.", "q": "Que demande cette affiche ?", "opts": ["D'être silencieux", "De fermer la porte", "D'éteindre la lumière"], "ans": "0"},
    {"text": "Ich bin Student und wohne mit zwei Freunden in einer Wohnung. Die Miete ist günstig.", "q": "Avec qui habite l'étudiant ?", "opts": ["Avec deux amis", "Avec ses parents", "Il habite seul"], "ans": "0"},
    {"text": "Im Park gibt es heute ein Fest für Kinder. Es beginnt um 15 Uhr, der Eintritt ist frei.", "q": "Que dit le texte sur l'entrée ?", "opts": ["Elle est gratuite", "Elle coûte 5 euros", "Elle coûte 2 euros"], "ans": "0"},
    {"text": "Guten Tag, ich möchte einen Tisch für vier Personen reservieren, heute um 20 Uhr.", "q": "Pour combien de personnes est la réservation ?", "opts": ["Quatre", "Deux", "Six"], "ans": "0"},
    {"text": "Mein Chef ist nett, aber ich habe viel Arbeit. Ich arbeite von 8 bis 17 Uhr.", "q": "À quelle heure la personne finit-elle de travailler ?", "opts": ["À 17h", "À 8h", "À 15h"], "ans": "0"},
    {"text": "Es ist Winter. Heute schneit es, und es ist minus fünf Grad kalt.", "q": "Quel temps fait-il aujourd'hui ?", "opts": ["Il neige et il fait froid", "Il fait chaud", "Il y a du soleil"], "ans": "0"},
    {"text": "Die Apotheke am Bahnhof hat auch am Sonntag geöffnet.", "q": "Quelle pharmacie est ouverte le dimanche ?", "opts": ["Celle de la gare", "Celle de l'école", "Aucune"], "ans": "0"},
    {"text": "Hallo Julia, ich habe zwei Karten für das Kino. Hast du am Freitag Zeit? Liebe Grüße, Mia", "q": "Que propose Mia à Julia ?", "opts": ["Aller au cinéma vendredi", "Aller au théâtre samedi", "Étudier ensemble"], "ans": "0"},
    {"text": "Das Zimmer hat ein Bett, einen Tisch und eine Lampe. Es hat keinen Fernseher.", "q": "Qu'est-ce qui manque dans la chambre ?", "opts": ["La télévision", "La lampe", "La table"], "ans": "0"},
    {"text": "Mein Vater ist 50 Jahre alt. Er ist Taxifahrer und fährt jeden Tag durch die Stadt.", "q": "Quel est le métier du père ?", "opts": ["Chauffeur de taxi", "Pilote", "Cuisinier"], "ans": "0"},
    {"text": "Entschuldigung, wir haben keine Milch mehr. Möchten Sie lieber Saft?", "q": "Que propose-t-on au client ?", "opts": ["Du jus", "Du café", "De l'eau"], "ans": "0"},
    {"text": "Wir sind am Strand. Das Meer ist warm, und die Sonne scheint. Es ist toll! Eure Lea", "q": "Où se trouve Lea ?", "opts": ["À la plage", "À la montagne", "En ville"], "ans": "0"},
    {"text": "Der Brief ist für Herrn Weber. Er wohnt im dritten Stock.", "q": "À quel étage habite M. Weber ?", "opts": ["Au troisième", "Au premier", "Au rez-de-chaussée"], "ans": "0"},
    {"text": "Ab nächster Woche beginnt die Schule schon um 7.45 Uhr und nicht mehr um 8 Uhr.", "q": "À quelle heure l'école commencera-t-elle la semaine prochaine ?", "opts": ["À 7h45", "À 8h", "À 8h45"], "ans": "0"},
    {"text": "Ich spreche Französisch und Englisch. Deutsch lerne ich noch.", "q": "Que dit la personne de l'allemand ?", "opts": ["Elle l'apprend encore", "Elle le parle déjà bien", "Elle ne veut pas l'apprendre"], "ans": "0"}
]

SCHREIBEN_EXTRA = [
    {"q": "Écris un message à une amie pour l'inviter à ta fête d'anniversaire samedi. (Liebe Anna, ...)", "min_words": 15, "must": [["hallo", "liebe", "lieber"], ["einlad", "party", "feier"], ["samstag", "geburtstag"]], "model": "Liebe Anna, ich habe am Samstag Geburtstag und mache eine Party. Ich möchte dich gern einladen. Kommst du um 18 Uhr zu mir? Viele Grüße, Tom"},
    {"q": "Écris un message à ton professeur pour dire que tu arrives en retard au cours parce que ton bus ne roule pas. (Guten Tag, ...)", "min_words": 14, "must": [["guten tag", "hallo", "liebe"], ["entschuldig", "leider", "tut mir leid"], ["spät", "bus"], ["kurs", "unterricht", "schule"]], "model": "Guten Tag, entschuldigen Sie bitte, ich komme heute leider zu spät zum Kurs. Mein Bus fährt nicht. Ich bin um zehn Uhr da. Danke und viele Grüße, Paul"},
    {"q": "Écris un message au cabinet médical : tu es malade et tu veux un rendez-vous. (Guten Tag, ...)", "min_words": 14, "must": [["guten tag", "hallo", "sehr geehrte"], ["krank", "fieber", "schmerz"], ["termin", "zeit"], ["arzt", "praxis"]], "model": "Guten Tag, ich bin krank und brauche einen Termin. Ich habe Kopfschmerzen und Fieber. Kann ich heute zum Arzt kommen? Danke, Maria Weber"},
    {"q": "Écris un message pour remercier une amie pour le dîner d'hier soir. (Liebe Sophie, ...)", "min_words": 12, "must": [["hallo", "liebe", "guten tag"], ["danke", "dank"], ["essen", "abend", "einladung"]], "model": "Liebe Sophie, vielen Dank für das Essen gestern Abend. Es war sehr lecker und der Abend war schön. Bis bald, Lena"},
    {"q": "Écris un e-mail à un hôtel pour demander le prix d'une chambre double pour trois nuits. (Guten Tag, ...)", "min_words": 15, "must": [["guten tag", "sehr geehrte", "hallo"], ["zimmer", "doppelzimmer"], ["preis", "kost"], ["nacht", "nächte"]], "model": "Guten Tag, ich möchte ein Doppelzimmer für drei Nächte buchen. Was kostet das Zimmer pro Nacht? Ist das Frühstück im Preis? Danke, Karl Meier"},
    {"q": "Écris un message à un restaurant pour réserver une table pour cinq personnes samedi soir. (Guten Tag, ...)", "min_words": 14, "must": [["guten tag", "hallo", "sehr geehrte"], ["tisch", "reserv"], ["personen", "uhr"], ["samstag", "abend"]], "model": "Guten Tag, ich möchte einen Tisch für fünf Personen reservieren. Wir kommen am Samstag um 19 Uhr. Vielen Dank, Familie Braun"},
    {"q": "Écris un message pour annuler un rendez-vous chez le coiffeur. (Guten Tag, ...)", "min_words": 12, "must": [["guten tag", "hallo", "liebe"], ["termin", "zeit"], ["absag", "nicht kommen", "leider"]], "model": "Guten Tag, ich habe morgen einen Termin bei Ihnen. Leider kann ich nicht kommen. Ich muss den Termin absagen. Danke, Eva Klein"},
    {"q": "Écris un message à un magasin pour demander si la veste existe dans une autre taille. (Guten Tag, ...)", "min_words": 12, "must": [["guten tag", "hallo", "sehr geehrte"], ["jacke", "mantel"], ["größ", "gross", "groß"]], "model": "Guten Tag, die Jacke im Schaufenster gefällt mir sehr. Haben Sie die Jacke auch in einer anderen Größe? Ich brauche Größe M. Danke, Ali"},
    {"q": "Écris un message à un ami pour lui dire que tu as déménagé dans une nouvelle ville. (Hallo, ...)", "min_words": 15, "must": [["hallo", "liebe", "lieber"], ["umgezogen", "umzug", "wohne", "neu"], ["stadt", "wohnung", "haus"]], "model": "Hallo Max, ich habe Neuigkeiten. Ich bin umgezogen und wohne jetzt in Köln. Die Stadt ist groß und meine Wohnung ist schön. Komm bald zu Besuch! Dein Jonas"},
    {"q": "Écris une carte postale à ta famille depuis tes vacances. (Liebe Familie, ...)", "min_words": 14, "must": [["liebe", "hallo", "grüße"], ["urlaub", "ferien", "meer", "hotel"], ["wetter", "sonn", "schön"]], "model": "Liebe Familie, viele Grüße aus dem Urlaub! Das Hotel ist toll und das Meer ist ganz nah. Das Wetter ist schön und die Sonne scheint jeden Tag. Bis bald, Eure Nina"},
    {"q": "Écris un e-mail à ton voisin : sa musique est trop forte le soir et tu demandes de la baisser. (Guten Tag, ...)", "min_words": 14, "must": [["guten tag", "hallo", "lieber"], ["laut", "musik", "lärm"], ["bitte", "könnten", "leiser"]], "model": "Guten Tag Herr Schulz, Ihre Musik ist abends sehr laut. Ich kann nicht schlafen. Könnten Sie bitte leiser sein? Vielen Dank, Frau Bauer"},
    {"q": "Écris un message à une collègue pour l'inviter à prendre un café demain. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "guten tag"], ["kaffee", "café"], ["morgen", "übermorgen"], ["zeit", "kommen", "komm"]], "model": "Hallo Petra, hast du morgen Zeit? Ich möchte dich zu einem Kaffee einladen. Wir können um drei Uhr im Café gehen. Bis morgen, Sara"},
    {"q": "Écris un message à un ami : tu as perdu tes clés et tu demandes de l'aide. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "guten tag"], ["schlüssel", "tür"], ["verloren", "weg"]], "model": "Hallo Tim, ich habe meinen Schlüssel verloren. Ich kann nicht in die Wohnung gehen. Kannst du mir bitte helfen? Danke, Jan"},
    {"q": "Écris un message pour t'excuser auprès d'un ami car tu as oublié son anniversaire. (Lieber Paul, ...)", "min_words": 12, "must": [["lieber", "liebe", "hallo"], ["entschuldig", "tut mir leid", "leider"], ["geburtstag", "vergessen"]], "model": "Lieber Paul, es tut mir leid, ich habe deinen Geburtstag vergessen. Ich wünsche dir nachträglich alles Gute. Wir feiern bald zusammen! Dein Leo"},
    {"q": "Écris un message à un ami pour proposer d'aller faire les courses samedi. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "lieber"], ["einkauf", "kaufen", "markt"], ["samstag", "abend"], ["kommst", "zeit"]], "model": "Hallo Ben, am Samstag gehe ich einkaufen. Ich brauche Brot, Obst und Milch. Kommst du mit? Hast du Zeit? Gruß, Marco"},
    {"q": "Écris un message à ta mère pour dire à quelle heure ton train arrive et demander qu'elle vienne te chercher. (Hallo Mama, ...)", "min_words": 14, "must": [["hallo", "liebe"], ["zug", "bahnhof"], ["uhr", "zeit", "früh"], ["abhol", "kommen", "bitte"]], "model": "Hallo Mama, mein Zug kommt um 15 Uhr am Bahnhof an. Kannst du mich bitte abholen? Ich habe zwei Taschen. Danke, Lisa"},
    {"q": "Écris un message pour remercier ton professeur d'allemand pour son aide. (Liebe Frau Roth, ...)", "min_words": 12, "must": [["liebe", "guten tag", "sehr geehrte"], ["danke", "dank"], ["hilfe", "geholfen", "deutsch"]], "model": "Liebe Frau Roth, vielen Dank für Ihre Hilfe. Ich lerne jetzt besser Deutsch. Der Kurs ist sehr gut. Viele Grüße, Samir"},
    {"q": "Écris un e-mail à une école de langues pour demander des informations sur un cours pour débutants. (Guten Tag, ...)", "min_words": 15, "must": [["guten tag", "sehr geehrte", "hallo"], ["kurs", "deutsch"], ["anfänger", "a1", "deutsch"], ["preis", "kost", "wann", "beginn"]], "model": "Guten Tag, ich möchte einen Deutschkurs für Anfänger machen. Wann beginnt der Kurs und was kostet er? Danke für Ihre Antwort, Ibrahim"},
    {"q": "Écris un message à un ami : tu as faim et tu proposes de manger une pizza ce soir. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "lieber"], ["pizza", "restaurant"], ["abend", "heute"], ["hunger", "essen", "komm"]], "model": "Hallo Sven, ich habe Hunger. Wollen wir heute Abend eine Pizza essen? Ich kenne ein gutes Restaurant. Kommst du mit? Gruß, Dani"},
    {"q": "Écris un message à ton chef : tu es malade et tu ne peux pas travailler aujourd'hui. (Guten Morgen, ...)", "min_words": 12, "must": [["guten morgen", "guten tag", "hallo", "sehr geehrte"], ["krank", "fieber", "schmerz"], ["arbeit", "heute", "morgen"]], "model": "Guten Morgen Herr Wolf, ich bin krank und kann heute nicht zur Arbeit kommen. Ich gehe zum Arzt. Ich rufe Sie morgen an. Danke, Eva Berg"},
    {"q": "Écris un message à ta voisine pour l'inviter à un barbecue dimanche. (Liebe Frau Lang, ...)", "min_words": 14, "must": [["hallo", "liebe", "guten tag"], ["grill", "essen", "einlad"], ["sonntag", "samstag", "freitag"]], "model": "Liebe Frau Lang, am Sonntag grille ich im Garten. Ich möchte Sie gern einladen. Wir essen um 13 Uhr. Kommen Sie bitte? Viele Grüße, Hans Roth"},
    {"q": "Écris un message à la réception d'un hôtel pour demander à quelle heure est le petit-déjeuner. (Guten Tag, ...)", "min_words": 10, "must": [["guten tag", "hallo"], ["frühstück", "essen"], ["wann", "uhr"], ["hotel", "zimmer"]], "model": "Guten Tag, ich wohne in Zimmer 12 in Ihrem Hotel. Wann gibt es das Frühstück? Bis wie viel Uhr ist es offen? Danke, Herr Nguyen"},
    {"q": "Écris un message à un ami pour lui présenter ta famille. (Hallo, ...)", "min_words": 15, "must": [["hallo", "liebe", "lieber"], ["familie", "schwester", "bruder", "mutter", "vater"], ["wohn", "heiß", "alt"]], "model": "Hallo Tom, ich erzähle dir von meiner Familie. Ich habe eine Schwester und einen Bruder. Meine Schwester heißt Anna und ist zwölf Jahre alt. Wir wohnen in Yaoundé. Dein Paul"},
    {"q": "Écris un message à un collègue : tu ne peux pas venir à la réunion de 15 heures, tu proposes 16 heures. (Hallo, ...)", "min_words": 14, "must": [["hallo", "guten tag", "liebe"], ["termin", "treffen", "besprechung"], ["uhr", "zeit", "früh"], ["leider", "nicht", "kann"]], "model": "Hallo Frank, ich kann leider nicht zum Treffen um 15 Uhr kommen. Ist 16 Uhr auch möglich? Ich habe dann Zeit. Danke, Julia"},
    {"q": "Écris un message à un ami pour lui demander de te prêter un livre. (Hallo, ...)", "min_words": 10, "must": [["hallo", "liebe", "lieber"], ["buch", "leihen"], ["leih", "brauche", "bitte"]], "model": "Hallo Chris, ich brauche das Buch für den Deutschkurs. Kannst du mir das Buch bitte leihen? Ich bringe es nächste Woche zurück. Danke, Emma"},
    {"q": "Écris un message à un ami pour parler de ton travail. (Hallo, ...)", "min_words": 15, "must": [["hallo", "liebe", "lieber"], ["arbeit", "beruf", "job"], ["gern", "gut", "nett", "viel"]], "model": "Hallo Lukas, wie geht es dir? Ich habe eine neue Arbeit in einem Hotel. Die Kollegen sind nett und ich arbeite gern dort. Ich habe aber viel zu tun. Dein Karim"},
    {"q": "Écris un message à un magasin en ligne : ton colis n'est pas arrivé après une semaine. (Guten Tag, ...)", "min_words": 15, "must": [["guten tag", "sehr geehrte", "hallo"], ["paket", "bestellung"], ["nicht", "leider", "kein"], ["woche", "tag", "bitte"]], "model": "Guten Tag, ich habe vor einer Woche ein Paket bestellt. Das Paket ist leider noch nicht da. Können Sie bitte prüfen, wo es ist? Danke, Frau Fischer"},
    {"q": "Écris un message à la gare : tu as perdu ton téléphone dans le train. (Guten Tag, ...)", "min_words": 12, "must": [["guten tag", "hallo", "sehr geehrte"], ["handy", "telefon"], ["verloren", "gefunden", "bahnhof", "zug"]], "model": "Guten Tag, ich habe mein Handy im Zug verloren. Es ist schwarz und hat eine rote Hülle. Haben Sie es gefunden? Danke, Herr Adler"},
    {"q": "Écris un message à un ami malade pour lui souhaiter un bon rétablissement. (Lieber Peter, ...)", "min_words": 12, "must": [["lieber", "liebe", "hallo"], ["gute besserung", "besser", "krank"], ["gesund", "hoffe", "besuch"]], "model": "Lieber Peter, ich höre, dass du krank bist. Gute Besserung! Ich hoffe, du bist bald wieder gesund. Ich besuche dich am Sonntag. Dein Max"},
    {"q": "Écris un message à ta famille pour souhaiter un joyeux Noël et une bonne année. (Liebe Familie, ...)", "min_words": 12, "must": [["liebe", "hallo"], ["frohe", "weihnacht", "neues jahr", "wünsche"], ["gesund", "glück", "alles gute"]], "model": "Liebe Familie, ich wünsche euch frohe Weihnachten und ein gutes neues Jahr. Bleibt gesund und glücklich! Alles Gute, Peter"},
    {"q": "Écris un message à un ami pour fixer un rendez-vous à la gare à une certaine heure. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "lieber"], ["bahnhof", "zug"], ["treffen", "abholen", "warte"], ["uhr", "zeit", "früh"]], "model": "Hallo Ali, wir treffen uns morgen am Bahnhof. Der Zug fährt um neun Uhr. Ich warte vor dem Eingang. Bis morgen, Daniel"},
    {"q": "Écris un message pour souhaiter un bon anniversaire à une amie. (Liebe Hanna, ...)", "min_words": 10, "must": [["liebe", "hallo"], ["glückwunsch", "geburtstag", "alles gute"], ["wünsche", "geschenk", "feiern"]], "model": "Liebe Hanna, herzlichen Glückwunsch zum Geburtstag! Ich wünsche dir alles Gute und viel Glück. Wir feiern bald zusammen. Deine Mia"},
    {"q": "Écris un e-mail à un propriétaire pour demander des informations sur un appartement et proposer une visite. (Guten Tag, ...)", "min_words": 15, "must": [["guten tag", "sehr geehrte"], ["wohnung", "miete"], ["miete", "kost", "preis"], ["besichtig", "termin", "anschauen"]], "model": "Guten Tag, ich interessiere mich für die Wohnung in der Lindenstraße. Wie hoch ist die Miete? Kann ich die Wohnung am Samstag besichtigen? Danke, Herr Yilmaz"},
    {"q": "Écris un message à un ami pour lui dire quel temps il fait chez toi. (Hallo, ...)", "min_words": 12, "must": [["hallo", "liebe", "lieber"], ["wetter", "regn", "sonn", "kalt"], ["hier", "bei uns", "heute"]], "model": "Hallo Tom, wie ist das Wetter bei dir? Hier regnet es seit drei Tagen und es ist kalt. Ich bleibe heute zu Hause. Dein Ben"},
    {"q": "Écris un message à une collègue pour raconter ton week-end. (Hallo, ...)", "min_words": 15, "must": [["hallo", "liebe", "guten morgen"], ["wochenende", "samstag", "sonntag"], ["fahr", "gehe", "spiel", "besuch", "mach"]], "model": "Hallo Nora, am Wochenende war es schön. Am Samstag besuche ich meine Eltern. Am Sonntag gehe ich mit Freunden in den Park und wir spielen Fußball. Und du? Gruß, Mark"},
    {"q": "Écris un message pour réserver un taxi pour l'aéroport demain matin. (Guten Tag, ...)", "min_words": 12, "must": [["guten tag", "hallo"], ["flughafen", "taxi"], ["uhr", "morgen", "heute"], ["bitte", "brauche", "möchte"]], "model": "Guten Tag, ich brauche morgen früh ein Taxi zum Flughafen. Es soll um sechs Uhr kommen. Bitte schreiben Sie mir kurz zurück. Danke, Herr Ali"},
    {"q": "Écris un message à un ami pour lui dire que tu apprends l'allemand. (Hallo, ...)", "min_words": 14, "must": [["hallo", "liebe", "lieber"], ["deutsch", "sprache"], ["lerne", "kurs", "schule"], ["gern", "schwer", "schön", "spaß"]], "model": "Hallo Kofi, ich lerne jetzt Deutsch. Ich habe einen Kurs am Abend. Die Grammatik ist ein bisschen schwer, aber ich lerne gern. Dein Paul"},
    {"q": "Écris un message à un ami pour lui demander à quelle heure commence le film au cinéma. (Hallo, ...)", "min_words": 10, "must": [["hallo", "liebe", "lieber"], ["kino", "film"], ["wann", "uhr", "zeit"]], "model": "Hallo Jonas, gehen wir heute ins Kino? Wann beginnt der Film? Um wie viel Uhr treffen wir uns? Antworte bitte bald, Tina"},
    {"q": "Écris un message pour remercier ta voisine qui t'a offert des fleurs. (Liebe Frau Hahn, ...)", "min_words": 10, "must": [["liebe", "guten tag", "hallo"], ["danke", "dank"], ["blume", "danke"]], "model": "Liebe Frau Hahn, vielen Dank für die schönen Blumen. Ich habe mich sehr gefreut. Sie sind jetzt auf meinem Tisch. Viele Grüße, Anna"},
    {"q": "Écris un message à une amie pour lui demander de s'occuper de ton chat pendant tes vacances. (Hallo, ...)", "min_words": 15, "must": [["hallo", "liebe", "lieber"], ["katze", "tier"], ["urlaub", "woche", "fahre"], ["bitte", "kannst", "hilf"]], "model": "Hallo Lara, ich fahre nächste Woche in den Urlaub. Kannst du bitte meine Katze füttern? Du bekommst den Schlüssel von mir. Danke, deine Sophie"}
]

SPRECHEN_EXTRA = [
    {"q": "Dis ton prénom et ton âge à voix haute.", "example": "Ich heiße Paul. Ich bin dreißig Jahre alt.", "pattern": "Ich heiße ... Ich bin ... Jahre alt"},
    {"q": "Dis où tu habites et quel est ton métier.", "example": "Ich wohne in Yaoundé. Ich arbeite als Lehrer.", "pattern": "Ich wohne in ... Ich arbeite als ..."},
    {"q": "Salue quelqu'un le matin et demande-lui comment il va (forme polie).", "example": "Guten Morgen! Wie geht es Ihnen?", "pattern": "Guten Morgen Wie geht es Ihnen / Guten Morgen Wie geht's"},
    {"q": "Dis au revoir le soir à un ami.", "example": "Gute Nacht! Bis morgen!", "pattern": "Gute Nacht / Auf Wiedersehen / Tschüss / Bis morgen"},
    {"q": "Remercie quelqu'un qui t'a aidé.", "example": "Vielen Dank! Das ist sehr nett.", "pattern": "Danke / Vielen Dank"},
    {"q": "Excuse-toi parce que tu as fait une erreur.", "example": "Entschuldigung, das tut mir leid.", "pattern": "Entschuldigung / Das tut mir leid"},
    {"q": "Parle de tes frères et soeurs.", "example": "Ich habe einen Bruder und eine Schwester.", "pattern": "Ich habe ... Bruder / Ich habe ... Schwester / Ich habe ... Geschwister / Ich habe keine Geschwister"},
    {"q": "Parle de ton hobby préféré.", "example": "Mein Hobby ist Fußball. Ich spiele gern Fußball.", "pattern": "Mein Hobby ist ... / Ich spiele gern ... / Ich höre gern ... / Ich lese gern ..."},
    {"q": "Dis l'heure qu'il est (par exemple trois heures et demie).", "example": "Es ist halb vier.", "pattern": "Es ist ... Uhr / Es ist halb ... / Es ist viertel ..."},
    {"q": "Demande le prix d'un objet dans un magasin.", "example": "Entschuldigung, was kostet das?", "pattern": "Was kostet das / Wie viel kostet das"},
    {"q": "Commande une boisson au café.", "example": "Ich hätte gern ein Wasser, bitte.", "pattern": "Ich hätte gern ... / Ich möchte ... / Ich nehme ..."},
    {"q": "Demande à un passant où se trouve la gare.", "example": "Entschuldigung, wo ist der Bahnhof?", "pattern": "Wo ist der Bahnhof"},
    {"q": "Dis quel jour nous sommes aujourd'hui et quel jour sera demain.", "example": "Heute ist Montag. Morgen ist Dienstag.", "pattern": "Heute ist ... Morgen ist ..."},
    {"q": "Dis quel temps il fait aujourd'hui.", "example": "Heute ist das Wetter schön. Die Sonne scheint.", "pattern": "Das Wetter ist ... / Es regnet / Es ist ... / Die Sonne scheint / Es schneit"},
    {"q": "Dis quelles langues tu parles.", "example": "Ich spreche Französisch und ein bisschen Deutsch.", "pattern": "Ich spreche ..."},
    {"q": "Compte de un à cinq en allemand.", "example": "Eins, zwei, drei, vier, fünf.", "pattern": "Eins zwei drei vier fünf"},
    {"q": "Dis le nom de deux couleurs en allemand.", "example": "Rot und blau.", "pattern": "rot / blau / grün / gelb / schwarz / weiß / braun"},
    {"q": "Dis ce que tu manges volontiers.", "example": "Ich esse gern Reis und Fisch.", "pattern": "Ich esse gern ... / Ich mag ..."},
    {"q": "Dis à quelle heure tu te lèves le matin.", "example": "Ich stehe um sechs Uhr auf.", "pattern": "Ich stehe um ... Uhr auf"},
    {"q": "Dis ce que tu manges au petit-déjeuner.", "example": "Zum Frühstück esse ich Brot und trinke Tee.", "pattern": "Zum Frühstück ... / Ich frühstücke ... / Ich esse ... zum Frühstück"},
    {"q": "Demande son nom à une personne (forme polie).", "example": "Wie heißen Sie?", "pattern": "Wie heißen Sie / Wie heißt du"},
    {"q": "Demande à une personne d'où elle vient.", "example": "Woher kommen Sie?", "pattern": "Woher kommen Sie / Woher kommst du"},
    {"q": "Dis dans quelle rue tu habites.", "example": "Ich wohne in der Hauptstraße.", "pattern": "Ich wohne in der ... / Meine Adresse ist ..."},
    {"q": "Dis que tu as faim et soif.", "example": "Ich habe Hunger und Durst.", "pattern": "Ich habe Hunger / Ich habe Durst"},
    {"q": "Dis que tu es fatigué et que tu vas au lit.", "example": "Ich bin müde. Ich gehe ins Bett.", "pattern": "Ich bin müde"},
    {"q": "Dis ce que tu veux acheter au marché.", "example": "Ich möchte ein Brot und zwei Äpfel kaufen.", "pattern": "Ich möchte ... / Ich hätte gern ... / Ich brauche ..."},
    {"q": "Dis les quatre premiers mois de l'année.", "example": "Januar, Februar, März, April.", "pattern": "Januar Februar März April"},
    {"q": "Dis en quel mois tu fêtes ton anniversaire.", "example": "Mein Geburtstag ist im Mai.", "pattern": "Mein Geburtstag ist ... / Ich habe im ... Geburtstag"},
    {"q": "Invite un ami à venir à ta fête.", "example": "Kommst du morgen zu meiner Party?", "pattern": "Kommst du ... / Möchtest du ... / Komm ..."},
    {"q": "Réponds poliment à une proposition de café : accepte ou refuse.", "example": "Ja, gern!", "pattern": "Ja gern / Nein danke / Ja bitte"},
    {"q": "Dis que tu n'as pas le temps aujourd'hui.", "example": "Heute habe ich keine Zeit.", "pattern": "Ich habe keine Zeit / Heute habe ich keine Zeit"},
    {"q": "Demande de l'aide poliment.", "example": "Können Sie mir helfen, bitte?", "pattern": "Können Sie mir helfen / Kannst du mir helfen"},
    {"q": "Dis que tu n'as pas compris.", "example": "Ich verstehe das nicht. Noch einmal, bitte.", "pattern": "Ich verstehe nicht / Ich verstehe das nicht / Noch einmal bitte"},
    {"q": "Dis tes horaires de travail.", "example": "Ich arbeite von acht bis siebzehn Uhr.", "pattern": "Ich arbeite von ... bis ..."},
    {"q": "Dis chez le médecin que tu as mal quelque part.", "example": "Ich habe Kopfschmerzen. Ich bin krank.", "pattern": "Ich habe ... / Ich bin krank / Mein ... tut weh"},
    {"q": "Dis comment tu vas au travail.", "example": "Ich fahre mit dem Bus zur Arbeit.", "pattern": "Ich fahre mit dem ... / Ich gehe zu Fuß"},
    {"q": "Dis quel est ton plat préféré.", "example": "Mein Lieblingsessen ist Pizza.", "pattern": "Mein Lieblingsessen ist ..."},
    {"q": "Dis quelle est ta nationalité.", "example": "Ich bin Kameruner. Ich komme aus Kamerun.", "pattern": "Ich bin ... / Ich komme aus ..."},
    {"q": "Dis que tu as un animal de compagnie.", "example": "Ich habe einen Hund. Er heißt Max.", "pattern": "Ich habe einen ... / Ich habe eine ... / Ich habe ein ... / Ich habe keinen ..."},
    {"q": "Demande l'addition au serveur.", "example": "Die Rechnung, bitte.", "pattern": "Die Rechnung bitte / Zahlen bitte / Ich möchte zahlen"}
]

HOREN_QUESTIONS = HOREN_QUESTIONS + HOREN_EXTRA
LESEN_QUESTIONS = LESEN_QUESTIONS + LESEN_EXTRA
SCHREIBEN_QUESTIONS = SCHREIBEN_QUESTIONS + SCHREIBEN_EXTRA
SPRECHEN_QUESTIONS = SPRECHEN_QUESTIONS + SPRECHEN_EXTRA

def _pick_index(bank, sess_key):
    """Tire une question au hasard, différente de la précédente."""
    last = session.get(sess_key + "_last")
    idx = random.randrange(len(bank))
    while len(bank) > 1 and idx == last:
        idx = random.randrange(len(bank))
    session[sess_key + "_last"] = idx
    return idx

def _save_goethe(module, score, total, extra=None):
    data = {"module": module, "score": score, "total": total, "level": "A1"}
    if extra:
        data.update(extra)
    db = get_db()
    db.execute("INSERT INTO goethe_exam(user_id, result_json) VALUES(?,?)",
               (session["user_id"], json.dumps(data, ensure_ascii=False)))
    db.commit()

def _choice_start(bank, sess_key):
    """Nouvelle question à choix : les propositions sont MÉLANGÉES (la bonne n'est plus toujours la 1re)."""
    idx = _pick_index(bank, sess_key)
    q = bank[idx]
    perm = list(range(len(q["opts"])))
    random.shuffle(perm)
    session[sess_key] = {"i": idx, "perm": perm}
    return q, perm

def _choice_state(bank, sess_key):
    st = session.get(sess_key)
    try:
        q = bank[int(st["i"])]
        perm = [int(p) for p in st["perm"]]
        if sorted(perm) != list(range(len(q["opts"]))):
            return None, None
        return q, perm
    except Exception:
        return None, None

def _choice_html(q, perm):
    return ''.join(
        f'<label class="quiz-opt"><input type="radio" name="rep" value="{pos}" required> {pos + 1}. {h(q["opts"][orig])}</label>'
        for pos, orig in enumerate(perm))

@app.route("/goethe")
@login_required
def goethe():
    body = f"""
    <h1>Examen Goethe A1 (Simulateur)</h1>
    <p style="margin-bottom:20px;color:var(--muted);">Cet examen blanc est structuré en 4 modules officiels. Chaque résultat est enregistré dans « Progrès ».</p>

    <div class="grid">
      <div class="card"><h2>1. Hören (Écoute)</h2><p>L'application lit un court dialogue. {len(HOREN_QUESTIONS)} questions.</p><a href="/goethe/horen" class="btn">Commencer</a></div>
      <div class="card"><h2>2. Lesen (Lecture)</h2><p>Lis un court texte et réponds. {len(LESEN_QUESTIONS)} questions.</p><a href="/goethe/lesen" class="btn">Commencer</a></div>
      <div class="card"><h2>3. Schreiben (Écriture)</h2><p>Écris un message simple. {len(SCHREIBEN_QUESTIONS)} sujets.</p><a href="/goethe/schreiben" class="btn">Commencer</a></div>
      <div class="card"><h2>4. Sprechen (Parler)</h2><p>Parle à voix haute, ta prononciation est notée. {len(SPRECHEN_QUESTIONS)} sujets.</p><a href="/goethe/sprechen" class="btn">Commencer</a></div>
    </div>
    """
    return page(layout("Examen Goethe A1", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/horen", methods=["GET","POST"])
@login_required
def goethe_horen():
    if request.method == "GET":
        q, perm = _choice_start(HOREN_QUESTIONS, "ex_horen")
    else:
        q, perm = _choice_state(HOREN_QUESTIONS, "ex_horen")
        if not q:
            return redirect(url_for("goethe_horen"))
        session.pop("ex_horen", None)
        rep = request.form.get("rep", "")
        good_pos = perm.index(int(q["ans"]))
        score = 1 if rep == str(good_pos) else 0
        _save_goethe("Hören", score, 1)
        correct = q["opts"][int(q["ans"])]
        feedback = "✔ Bonne réponse !" if score == 1 else f"✘ Mauvaise réponse. C'était : {h(correct)}"
        body = f"""
        <h1>Hören (Écoute) - Résultat</h1>
        <div class="card">
          <div class="flash {'success' if score==1 else 'danger'}">{feedback}</div>
          <p><b>Dialogue :</b> {h(q['audio'])}</p>
          <div style="margin:12px 0;">{say_btn("🔊 Réécouter", "de", "", q['audio'], css="btn ghost")}</div>
          <a href="/goethe/horen" class="btn">Question suivante</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return page(layout("Résultat Hören", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Hören (Écoute)</h1>
    <div class="card">
      <p>Écoute attentivement ce dialogue :</p>
      <div style="background:var(--sky-light);padding:16px;border-radius:10px;margin:14px 0;">
        {say_btn("🔊 Écouter le dialogue", "de", "", q['audio'])}
      </div>
      <form method="post">
        <h3>{h(q['q'])}</h3>
        {_choice_html(q, perm)}
        <button class="btn ok" type="submit" style="margin-top:14px">Valider</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    """
    return page(layout("Hören", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/lesen", methods=["GET","POST"])
@login_required
def goethe_lesen():
    if request.method == "GET":
        q, perm = _choice_start(LESEN_QUESTIONS, "ex_lesen")
    else:
        q, perm = _choice_state(LESEN_QUESTIONS, "ex_lesen")
        if not q:
            return redirect(url_for("goethe_lesen"))
        session.pop("ex_lesen", None)
        rep = request.form.get("rep", "")
        good_pos = perm.index(int(q["ans"]))
        score = 1 if rep == str(good_pos) else 0
        _save_goethe("Lesen", score, 1)
        correct = q["opts"][int(q["ans"])]
        feedback = "✔ Bonne réponse !" if score == 1 else f"✘ Mauvaise réponse. C'était : {h(correct)}"
        body = f"""
        <h1>Lesen (Lecture) - Résultat</h1>
        <div class="card">
          <div class="flash {'success' if score==1 else 'danger'}">{feedback}</div>
          <p><b>Texte :</b> {h(q['text'])}</p>
          <a href="/goethe/lesen" class="btn">Question suivante</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return page(layout("Résultat Lesen", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Lesen (Lecture)</h1>
    <div class="card">
      <p>Lis ce message :</p>
      <div style="background:var(--sky-light);padding:16px;border-radius:10px;margin:14px 0;font-style:italic;">
        "{h(q['text'])}"
      </div>
      <form method="post">
        <h3>{h(q['q'])}</h3>
        {_choice_html(q, perm)}
        <button class="btn ok" type="submit" style="margin-top:14px">Valider</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    """
    return page(layout("Lesen", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/schreiben", methods=["GET","POST"])
@login_required
def goethe_schreiben():
    if request.method == "GET":
        idx = _pick_index(SCHREIBEN_QUESTIONS, "ex_schreiben")
        session["ex_schreiben"] = {"i": idx}
        q = SCHREIBEN_QUESTIONS[idx]
    else:
        try:
            q = SCHREIBEN_QUESTIONS[int(session.get("ex_schreiben", {}).get("i"))]
        except Exception:
            return redirect(url_for("goethe_schreiben"))
        session.pop("ex_schreiben", None)
        rep = request.form.get("rep", "").strip()[:1500]
        words = len(rep.split())
        low = rep.lower()
        groups = q.get("must") or []
        hit = [any(alt in low for alt in g) for g in groups]
        got, need = sum(hit), len(groups)
        enough = words >= q["min_words"]
        ok = enough and (need == 0 or got / need >= 0.6)
        _save_goethe("Schreiben", 1 if ok else 0, 1, {"detail": f"{words} mots, {got}/{need} idées"})
        if ok:
            feedback = "✔ Bon travail !"
        elif not enough:
            feedback = f"✘ C'est un peu court : {words} mot(s), vise au moins {q['min_words']} mots."
        else:
            feedback = f"✘ Il manque des éléments demandés par la consigne ({got}/{need} idées trouvées). Relis la consigne."
        model = f'<p style="margin-top:10px;"><b>Modèle de réponse :</b> {h(q["model"])}</p>' if q.get("model") else ""
        body = f"""
        <h1>Schreiben (Écriture) - Résultat</h1>
        <div class="card">
          <div class="flash {'success' if ok else 'danger'}">{feedback}</div>
          <p><b>Ta réponse :</b> {h(rep)}</p>
          {model}
          <p style="color:var(--muted);margin-top:10px;">Note : cette correction vérifie la longueur et la présence des idées demandées. Dans un vrai examen, un correcteur humain évalue aussi la grammaire et le vocabulaire.</p>
          <a href="/goethe/schreiben" class="btn">Exercice suivant</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return page(layout("Résultat Schreiben", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Schreiben (Écriture)</h1>
    <div class="card">
      <p><b>Consigne :</b> {h(q['q'])}</p>
      <form method="post">
        <label>Ton message :</label>
        <textarea name="rep" rows="4" placeholder="Écris en allemand ici..." required></textarea>
        <button class="btn ok" type="submit">Valider</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    """
    return page(layout("Schreiben", body, {"is_admin": session.get("is_admin")}))

@app.route("/goethe/sprechen", methods=["GET","POST"])
@login_required
def goethe_sprechen():
    if request.method == "GET":
        idx = _pick_index(SPRECHEN_QUESTIONS, "ex_sprechen")
        session["ex_sprechen"] = {"i": idx}
        q = SPRECHEN_QUESTIONS[idx]
    else:
        try:
            q = SPRECHEN_QUESTIONS[int(session.get("ex_sprechen", {}).get("i"))]
        except Exception:
            return redirect(url_for("goethe_sprechen"))
        session.pop("ex_sprechen", None)
        heard = request.form.get("heard", "").strip()[:300]
        pattern = q.get("pattern") or ""
        if not heard:
            verdict = ('<div class="flash warning">Aucune réponse enregistrée : exercice non noté. '
                       'Utilise le micro 🎤 (Chrome ou Edge) ou écris ce que tu as dit.</div>')
        elif not pattern:
            verdict = '<div class="flash success">✔ Exercice fait. Cette consigne n\'est pas notée automatiquement : compare avec l\'exemple.</div>'
        else:
            score = _score_pronunciation(pattern, heard)
            ok = score >= 60
            _save_goethe("Sprechen", 1 if ok else 0, 1, {"pct": score})
            cls = "res-ok" if score >= 85 else ("res-mid" if score >= 60 else "res-bad")
            verdict = (f'<div class="flash {"success" if ok else "danger"}">{"✔ Bien joué !" if ok else "✘ À retravailler."}</div>'
                       f'<p>Score de prononciation : <span class="res-score {cls}">{score}%</span></p>'
                       f'<p>Neferti a compris : « {h(heard)} »</p>')
        body = f"""
        <h1>Sprechen (Parler) - Résultat</h1>
        <div class="card">
          {verdict}
          <p style="margin-top:10px;"><b>Exemple :</b> {h(q['example'])}</p>
          <div style="margin:12px 0;">{say_btn("🔊 Écouter l'exemple", "de", "", q['example'], css="btn ghost")}</div>
          <p style="color:var(--muted);margin-top:10px;">Dans un vrai examen Goethe, l'examinateur t'écoute et évalue ta prononciation.</p>
          <a href="/goethe/sprechen" class="btn">Exercice suivant</a>
          <a href="/goethe" class="btn ghost">Retour</a>
        </div>
        """
        return page(layout("Résultat Sprechen", body, {"is_admin": session.get("is_admin")}))

    body = f"""
    <h1>Sprechen (Parler)</h1>
    <div class="card">
      <h2>Consigne</h2>
      <p>{h(q['q'])}</p>
      <div class="sp-box">
        <p style="margin-bottom:10px;"><i>Exemple : {h(q['example'])}</i></p>
        {say_btn("🔊 Écouter l'exemple", "de", "", q['example'])}
      </div>
      <form method="post" id="sp-form">
        <div class="sp-actions">
          <button type="button" class="mic-btn" id="sp-mic" title="Répondre à voix haute">🎤</button>
          <div class="neferti-status" id="sp-status">Clique sur le micro et réponds en allemand (Chrome ou Edge).</div>
        </div>
        <label>Ce que tu as dit (tu peux corriger ou l'écrire toi-même) :</label>
        <input name="heard" id="sp-heard" placeholder="Ta réponse en allemand…" autocomplete="off">
        <button class="btn ok" type="submit">Valider ma réponse</button>
      </form>
    </div>
    <a href="/goethe" class="btn ghost">← Retour</a>
    <script>
    (function(){{
      var mic = document.getElementById('sp-mic');
      var st = document.getElementById('sp-status');
      var inp = document.getElementById('sp-heard');
      if (!mic) return;
      if (!window.NefertiSupported) {{
        st.textContent = "Reconnaissance vocale indisponible ici : écris ta réponse ci-dessous.";
      }}
      mic.addEventListener('click', function(){{
        if (!window.NefertiSupported) {{ inp.focus(); return; }}
        mic.classList.add('listening');
        st.textContent = "🎙️ Je t'écoute… parle en allemand !";
        window.NefertiStartListening(function(text){{
          inp.value = text;
          st.textContent = "✅ J'ai entendu : « " + text + " ». Clique sur Valider.";
        }}, function(err){{
          mic.classList.remove('listening');
          if (err && err !== 'aborted' && err !== 'no-speech') st.textContent = "⚠️ Erreur micro : " + err + ". Réessaie ou écris ta réponse.";
          else if (err === 'no-speech') st.textContent = "Je n'ai rien entendu. Réessaie.";
        }});
      }});
    }})();
    </script>
    """
    return page(layout("Sprechen", body, {"is_admin": session.get("is_admin")}))

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
    nomakk_count = db.execute("SELECT COUNT(*) FROM nomakk_sections").fetchone()[0]
    neferti_scenarios_count = db.execute("SELECT COUNT(*) FROM neferti_scenarios").fetchone()[0]
    neferti_users_count = db.execute("SELECT COUNT(DISTINCT user_id) FROM neferti_history").fetchone()[0]
    vocab_count = db.execute("SELECT COUNT(*) FROM vocab").fetchone()[0]
    dialogues_count = db.execute("SELECT COUNT(*) FROM dialogues").fetchone()[0]
    users_html = "".join(
        f"<tr><td>{u['id']}</td><td>{h(u['name'])}</td><td>{h(u['email'])}</td>"
        f"<td>{'Oui' if u['is_admin'] else 'Non'}</td><td>{h(str(u['created_at']))}</td>"
        f"<td><form method=\"post\" action=\"{url_for('admin_reset_password', uid=u['id'])}\" "
        f"onsubmit=\"return confirm('Générer un nouveau mot de passe temporaire pour cet utilisateur ?')\">"
        f"<button class=\"btn ghost\" type=\"submit\" style=\"padding:6px 12px;font-size:12px\">🔑 Réinitialiser</button></form></td></tr>"
        for u in users
    )
    body = f"""
    <h1>Tableau de bord Admin</h1>
    <div class="stat-grid" style="margin-bottom:18px">
      <div class="stat"><div class="num">{len(users)}</div><div class="lbl">Étudiants</div></div>
      <div class="stat"><div class="num">{lessons_count}</div><div class="lbl">Leçons</div></div>
      <div class="stat"><div class="num">{vocab_count}</div><div class="lbl">Mots de vocabulaire</div></div>
      <div class="stat"><div class="num">{dialogues_count}</div><div class="lbl">Dialogues</div></div>
      <div class="stat"><div class="num">{quiz_count}</div><div class="lbl">Examens Goethe</div></div>
      <div class="stat"><div class="num">{speak_count}</div><div class="lbl">Phrases "Parler"</div></div>
      <div class="stat"><div class="num">{ess_count}</div><div class="lbl">Fiches Essentiels</div></div>
      <div class="stat"><div class="num">{nomakk_count}</div><div class="lbl">Sections NOM/AKK</div></div>
      <div class="stat"><div class="num">{neferti_scenarios_count}</div><div class="lbl">Scénarios Neferti</div></div>
      <div class="stat"><div class="num">{neferti_users_count}</div><div class="lbl">Users Neferti</div></div>
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
      <p style="color:var(--muted);font-size:13px;margin-bottom:10px;">« Réinitialiser » génère un mot de passe temporaire (affiché une seule fois) à transmettre à l'étudiant, qui pourra le changer dans « Mon compte ».</p>
      <div style="overflow-x:auto;">
      <table><thead><tr><th>ID</th><th>Nom</th><th>Email</th><th>Admin</th><th>Inscrit le</th><th>Mot de passe</th></tr></thead>
      <tbody>{users_html}</tbody></table>
      </div>
    </div>
    """
    return page(layout("Admin", body, {"is_admin": True}))

@app.route("/admin/add_lesson", methods=["POST"])
@admin_required
def admin_add_lesson():
    cat = request.form.get("category","").strip()
    de = request.form.get("german","").strip()
    fr = request.form.get("french","").strip()
    if cat and de and fr:
        db = get_db()
        nxt = db.execute("SELECT COALESCE(MAX(order_index), -1) + 1 FROM lessons").fetchone()[0]
        db.execute("INSERT INTO lessons(category,title,french,german,order_index) VALUES(?,?,?,?,?)",
                   (cat,de,fr,de,nxt))
        db.commit()
        flash("Leçon ajoutée.","success")
    else:
        flash("Champs manquants.","danger")
    return redirect(url_for("admin"))

@app.route("/admin/reset_password/<int:uid>", methods=["POST"])
@admin_required
def admin_reset_password(uid):
    db = get_db()
    u = db.execute("SELECT id, name, email FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        flash("Utilisateur introuvable.","danger")
        return redirect(url_for("admin"))
    temp = secrets.token_urlsafe(8) + "Aa1"
    db.execute("UPDATE users SET password=? WHERE id=?", (hash_pwd(temp), uid))
    db.commit()
    flash(f"Mot de passe temporaire pour {u['email']} : {temp} (note-le maintenant, il ne sera plus affiché).","success")
    return redirect(url_for("admin"))

# ---------------------------------------------------------
# MON COMPTE (changer le mot de passe, supprimer le compte)
# ---------------------------------------------------------
@app.route("/compte")
@login_required
def compte():
    db = get_db()
    u = db.execute("SELECT name, email, created_at FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not u:
        session.clear()
        return redirect(url_for("login"))
    if session.get("is_admin"):
        delete_card = """
        <div class="card"><h2>Supprimer mon compte</h2>
        <p style="color:var(--muted);">Le compte administrateur ne peut pas être supprimé depuis cette page.</p></div>"""
    else:
        delete_card = f"""
        <div class="card danger-zone">
          <h2>Supprimer mon compte</h2>
          <p style="color:var(--muted);margin-bottom:10px;">Efface définitivement ton compte, ta progression, tes résultats d'examen et la mémoire de Neferti. Cette action est irréversible.</p>
          <form method="post" action="{url_for('compte_supprimer')}" onsubmit="return confirm('Supprimer définitivement ton compte ?')">
            <label>Mot de passe</label><input name="password" type="password" required autocomplete="current-password">
            <button class="btn danger" type="submit">Supprimer mon compte</button>
          </form>
        </div>"""
    body = f"""
    <h1>Mon compte 👤</h1>
    <div class="card">
      <p><b>Nom :</b> {h(u['name'])}</p>
      <p><b>Email :</b> {h(u['email'])}</p>
      <p><b>Inscrit le :</b> {h(str(u['created_at']))}</p>
    </div>
    <div class="card">
      <h2>Changer mon mot de passe</h2>
      <form method="post" action="{url_for('compte_mot_de_passe')}">
        <label>Mot de passe actuel</label><input name="current" type="password" required autocomplete="current-password">
        <label>Nouveau mot de passe</label><input name="new" type="password" required autocomplete="new-password" placeholder="Min. 8 car., Maj., min., chiffre">
        <button class="btn" type="submit">Changer</button>
      </form>
    </div>
    {delete_card}
    """
    return page(layout("Mon compte", body, {"is_admin": session.get("is_admin")}))

@app.route("/compte/mot-de-passe", methods=["POST"])
@login_required
def compte_mot_de_passe():
    db = get_db()
    uid = session["user_id"]
    k_ip, k_id = _login_keys("pw%d" % uid)
    if _login_blocked(db, k_ip, k_id):
        flash("Trop de tentatives. Réessaie dans quelques minutes.","danger")
        return redirect(url_for("compte"))
    row = db.execute("SELECT password FROM users WHERE id=?", (uid,)).fetchone()
    current = request.form.get("current","")
    new = request.form.get("new","")
    if not row or not check_pwd(row["password"], current):
        _login_fail(db, k_ip, k_id)
        flash("Mot de passe actuel incorrect.","danger")
    elif not validate_password(new):
        flash("Nouveau mot de passe trop faible. Il faut au moins 8 caractères, une majuscule, une minuscule et un chiffre.","danger")
    else:
        db.execute("UPDATE users SET password=? WHERE id=?", (hash_pwd(new), uid))
        db.commit()
        flash("Mot de passe modifié.","success")
    return redirect(url_for("compte"))

@app.route("/compte/supprimer", methods=["POST"])
@login_required
def compte_supprimer():
    if session.get("is_admin"):
        flash("Le compte administrateur ne peut pas être supprimé.","danger")
        return redirect(url_for("compte"))
    db = get_db()
    uid = session["user_id"]
    k_ip, k_id = _login_keys("pw%d" % uid)
    if _login_blocked(db, k_ip, k_id):
        flash("Trop de tentatives. Réessaie dans quelques minutes.","danger")
        return redirect(url_for("compte"))
    row = db.execute("SELECT password FROM users WHERE id=?", (uid,)).fetchone()
    if not row or not check_pwd(row["password"], request.form.get("password","")):
        _login_fail(db, k_ip, k_id)
        flash("Mot de passe incorrect : compte non supprimé.","danger")
        return redirect(url_for("compte"))
    for table in ("progress", "goethe_exam", "neferti_memory", "neferti_history"):
        db.execute(f"DELETE FROM {table} WHERE user_id=?", (uid,))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    session.clear()
    flash("Ton compte et toutes tes données ont été supprimés.","success")
    return redirect(url_for("index"))

# ---------------------------------------------------------
# LANCEMENT
# ---------------------------------------------------------
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("NATHO_DEBUG") == "1", host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
